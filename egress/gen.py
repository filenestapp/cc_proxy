#!/usr/bin/env python3
"""Generate sing-box configs for the multi-IP egress node from an inventory file.

Commands:
  server   INVENTORY            -> exit-node config (VLESS+Reality in, one bound direct outbound per egress IP)
  client   INVENTORY DEVICE     -> client config; --mode proxy (local SOCKS/HTTP port), domain (fake-IP TUN,
                                   default route untouched) or app (full TUN, split by process and domain)
  ips      INVENTORY            -> egress IPs the host must carry, one per line
  check    INVENTORY            -> validate only

Only the Python standard library is used, so it runs on a bare server (Python 3.8+).
"""
import argparse
import ipaddress
import json
import sys
import uuid as uuidlib

FLOW = "xtls-rprx-vision"
DEFAULT_BLOCK_CIDRS = ["169.254.169.254/32"]


class InventoryError(Exception):
    pass


def load(path):
    with open(path, encoding="utf-8") as f:
        inv = json.load(f)
    validate(inv)
    return inv


def validate(inv):
    errors = []
    server = inv.get("server") or {}
    for key in ("public_host", "reality"):
        if key not in server:
            errors.append("server.%s is required" % key)
    shared_port = server.get("listen_port")
    reality = server.get("reality") or {}
    for key in ("private_key", "public_key", "short_id", "server_name", "handshake_server"):
        if not reality.get(key):
            errors.append("server.reality.%s is required" % key)

    egress = {}
    for entry in inv.get("egress_ips", []):
        ip = entry.get("ip", "")
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            errors.append("egress_ips: %r is not an IPv4 address" % ip)
            continue
        if ip in egress:
            errors.append("egress_ips: %s listed twice" % ip)
        status = entry.get("status", "available")
        if status not in ("available", "cooldown", "banned"):
            errors.append("egress_ips: %s has unknown status %r" % (ip, status))
        egress[ip] = status

    users_by_ip = {}
    seen_users, seen_devices, seen_uuids = set(), set(), set()
    ports = {shared_port: "server.listen_port"} if shared_port else {}
    for user in inv.get("users", []):
        name = user.get("name", "")
        if not name or "/" in name:
            errors.append("user name %r must be non-empty and contain no '/'" % name)
        if name in seen_users:
            errors.append("user %s listed twice" % name)
        seen_users.add(name)
        mode = user.get("mode", "exclusive")
        if mode not in ("exclusive", "shared"):
            errors.append("user %s: mode must be exclusive or shared" % name)
        ip = user.get("egress_ip")
        if ip is not None:
            if ip not in egress:
                errors.append("user %s: egress_ip %s is not in egress_ips" % (name, ip))
            elif egress[ip] != "available":
                errors.append("user %s: egress_ip %s is %s and cannot be assigned" % (name, ip, egress[ip]))
            users_by_ip.setdefault(ip, []).append((name, mode))
        port = user.get("port")
        if port is None:
            if not shared_port:
                errors.append("user %s has no port and server.listen_port is not set" % name)
        elif not isinstance(port, int) or not 1 <= port <= 65535:
            errors.append("user %s: port must be an integer 1-65535" % name)
        elif port in ports:
            errors.append("user %s: port %d is already used by %s" % (name, port, ports[port]))
        else:
            ports[port] = "user " + name
        for dev in user.get("devices", []):
            dname = dev.get("name", "")
            if not dname:
                errors.append("user %s: device without name" % name)
            if (name, dname) in seen_devices:
                errors.append("device %s of user %s listed twice" % (dname, name))
            seen_devices.add((name, dname))
            try:
                u = str(uuidlib.UUID(dev.get("uuid", "")))
            except ValueError:
                errors.append("device %s: invalid uuid" % dname)
                continue
            if u in seen_uuids:
                errors.append("device %s: uuid reused" % dname)
            seen_uuids.add(u)

    for ip, holders in users_by_ip.items():
        if len(holders) > 1 and any(mode != "shared" for _, mode in holders):
            names = ", ".join(n for n, _ in holders)
            errors.append("egress_ip %s is held by several users (%s); all must use mode=shared" % (ip, names))

    if errors:
        raise InventoryError("\n".join(errors))


def credential_name(user, device):
    # auth_user matches this name; one entry per device so a device can be revoked alone.
    return "%s/%s" % (user["name"], device["name"])


def outbound_tag(ip):
    return "egress-" + ip


def user_inbound_tag(user):
    return "user-" + user["name"]


def vless_inbound(server, tag, port, users):
    reality = server["reality"]
    return {
        "type": "vless",
        "tag": tag,
        "listen": server.get("listen", "::"),
        "listen_port": port,
        "users": users,
        "tls": {
            "enabled": True,
            "server_name": reality["server_name"],
            "reality": {
                "enabled": True,
                "handshake": {
                    "server": reality["handshake_server"],
                    "server_port": reality.get("handshake_port", 443),
                },
                "private_key": reality["private_key"],
                "short_id": [reality["short_id"]],
            },
        },
    }


def build_server(inv):
    """Users with a "port" get their own inbound (routed by inbound tag); the others share
    server.listen_port and are routed by credential name."""
    server = inv["server"]

    shared_users, own_inbounds, route_rules = [], [], []
    used_ips = []
    for user in inv.get("users", []):
        active = [d for d in user.get("devices", []) if not d.get("revoked")]
        names = [credential_name(user, d) for d in active]
        creds = [{"name": cname, "uuid": dev["uuid"], "flow": FLOW} for dev, cname in zip(active, names)]
        ip = user.get("egress_ip")
        if user.get("port"):
            # The inbound exists even without devices or an IP, so the port is always held for this user.
            tag = user_inbound_tag(user)
            own_inbounds.append(vless_inbound(server, tag, user["port"], creds))
            match = {"inbound": [tag]}
        elif active:
            shared_users += creds
            match = {"auth_user": names}
        else:
            continue
        if ip:
            route_rules.append(dict(match, outbound=outbound_tag(ip)))
            if ip not in used_ips:
                used_ips.append(ip)
        # Users without an egress IP get no rule and fall through to the final reject.

    # Exits are IPv4-only: an IPv6 destination would leave from the host's default IPv6 source, outside the
    # user's assigned address (sing-box dials IPv6 separately from inet4_bind_address).
    block_rules = [{"ip_cidr": ["::/0"], "action": "reject"}]
    if server.get("block_private", True):
        block_rules.append({"ip_is_private": True, "action": "reject"})
    block_cidrs = server.get("block_cidrs", DEFAULT_BLOCK_CIDRS)
    if block_cidrs:
        block_rules.append({"ip_cidr": block_cidrs, "action": "reject"})

    outbounds = [
        {"type": "direct", "tag": outbound_tag(ip), "inet4_bind_address": ip}
        for ip in used_ips
    ]
    # sing-box needs at least one outbound; it is never selected because route.final is a reject.
    outbounds.append({"type": "block", "tag": "deny"})

    return {
        "log": {"level": server.get("log_level", "info"), "timestamp": True},
        "dns": {
            "servers": [{"type": "local", "tag": "local"}],
            # Resolve AAAA-free: the egress path is IPv4-only in the first version.
            "strategy": "ipv4_only",
        },
        "inbounds": ([vless_inbound(server, "vless-in", server["listen_port"], shared_users)]
                     if server.get("listen_port") else []) + own_inbounds,
        "outbounds": outbounds,
        "route": {
            # Destination IP rules only see destinations that are IPs. Resolve domains first (IPv4 only), or a name
            # that resolves to a private or blocked address would slip past block_rules.
            "rules": [{"action": "sniff"}, {"action": "resolve", "strategy": "ipv4_only"}]
                     + block_rules + route_rules,
            # Unmatched credentials (no egress IP) are dropped instead of leaving via the host's main IP.
            "final": "deny",
            "default_domain_resolver": {"server": "local", "strategy": "ipv4_only"},
        },
    }


def find_device(inv, device_name, user_name=None):
    """Device names are unique per user; pass user_name when several users may use the same name."""
    found = [(user, dev) for user in inv.get("users", []) for dev in user.get("devices", [])
             if dev["name"] == device_name and user_name in (None, user["name"])]
    if not found:
        raise InventoryError("device %s not found" % device_name)
    if len(found) > 1:
        raise InventoryError("device name %s is used by several users; give the user name" % device_name)
    return found[0]


FAKEIP_RANGE = "198.18.0.0/15"
TUN_ADDRESS = "172.19.0.1/30"
TUN_DNS = "172.19.0.2"  # resolver address handed to the OS; queries to it enter the TUN and are hijacked
CLIENT_MODES = ("proxy", "domain", "app")


def client_policy(inv):
    p = inv.get("client_policy") or {}
    return {
        "domain_suffix": p.get("domain_suffix", []),
        "process_name": p.get("process_name", []),
        "process_path": p.get("process_path", []),
        "block_quic": p.get("block_quic", True),
        # "dhcp" = resolvers handed out by the local network; or an IP such as "192.168.1.1".
        "direct_dns": p.get("direct_dns", "dhcp"),
    }


def direct_dns_server(value):
    if value == "dhcp":
        return {"type": "dhcp", "tag": "direct-dns"}
    if value == "local":
        return {"type": "local", "tag": "direct-dns"}
    return {"type": "udp", "tag": "direct-dns", "server": value}


def tunnel_rules(policy, mode):
    """Route rules that send matching traffic to the egress outbound."""
    matchers = [{"domain_suffix": policy["domain_suffix"]}] if policy["domain_suffix"] else []
    matchers.append({"ip_cidr": [FAKEIP_RANGE]})
    if mode == "app":
        if policy["process_name"]:
            matchers.append({"process_name": policy["process_name"]})
        if policy["process_path"]:
            matchers.append({"process_path": policy["process_path"]})
    rules = []
    if policy["block_quic"]:
        # Force QUIC users back to TCP so the path is predictable.
        rules += [dict(m, network="udp", port=443, action="reject") for m in matchers]
    rules += [dict(m, outbound="egress") for m in matchers]
    return rules


def build_client(inv, device_name, listen="127.0.0.1", port=2080, allow_revoked=False, mode="proxy",
                 user_name=None):
    user, dev = find_device(inv, device_name, user_name)
    if dev.get("revoked") and not allow_revoked:
        raise InventoryError("device %s is revoked" % device_name)
    if mode not in CLIENT_MODES:
        raise InventoryError("mode must be one of %s" % ", ".join(CLIENT_MODES))
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "local-in", "listen": listen, "listen_port": port}],
        "outbounds": [egress_outbound(inv, user, dev), {"type": "direct", "tag": "direct"}],
        "route": {"final": "egress"},
    }
    if mode == "proxy":
        return config

    policy = client_policy(inv)
    if not policy["domain_suffix"] and mode == "domain":
        raise InventoryError("client_policy.domain_suffix is empty; domain mode would tunnel nothing")
    if mode == "app" and not (policy["process_name"] or policy["process_path"] or policy["domain_suffix"]):
        raise InventoryError("client_policy has no process or domain rules; app mode would tunnel nothing")

    dns_rules = []
    if policy["domain_suffix"]:
        # No AAAA for tunnelled names: the egress path is IPv4-only, and a real AAAA would leak around the tunnel.
        dns_rules.append({"domain_suffix": policy["domain_suffix"], "query_type": ["AAAA"],
                          "action": "predefined", "rcode": "NOERROR"})
        dns_rules.append({"domain_suffix": policy["domain_suffix"], "server": "fakeip"})

    tun = {"type": "tun", "tag": "tun-in", "address": [TUN_ADDRESS], "auto_route": True, "stack": "mixed"}
    if mode == "domain":
        # Only the fake-IP range and the TUN's own /30 are routed; the default route stays as it was.
        tun["route_address"] = [FAKEIP_RANGE, "172.19.0.0/30"]
    else:
        tun["strict_route"] = True

    config["inbounds"] = [tun]
    config["dns"] = {
        "servers": [
            {"type": "fakeip", "tag": "fakeip", "inet4_range": FAKEIP_RANGE},
            direct_dns_server(policy["direct_dns"]),
        ],
        "rules": dns_rules,
        "final": "direct-dns",
    }
    config["route"] = {
        "rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}] + tunnel_rules(policy, mode),
        "final": "direct",
        "auto_detect_interface": True,
        "default_domain_resolver": "direct-dns",
    }
    if mode == "app":
        config["route"]["find_process"] = True
    # Keep fake-IP mappings across restarts so cached answers in apps stay valid.
    config["experimental"] = {"cache_file": {"enabled": True, "store_fakeip": True}}
    return config


def egress_outbound(inv, user, dev):
    server = inv["server"]
    reality = server["reality"]
    return {
        "type": "vless",
        "tag": "egress",
        "server": server["public_host"],
        "server_port": user.get("port") or server["listen_port"],
        "uuid": dev["uuid"],
        "flow": FLOW,
        "tls": {
            "enabled": True,
            "server_name": reality["server_name"],
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {
                "enabled": True,
                "public_key": reality["public_key"],
                "short_id": reality["short_id"],
            },
        },
    }


def egress_ips(inv):
    return [e["ip"] for e in inv.get("egress_ips", [])]


def write(obj, out):
    text = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    if out in (None, "-"):
        sys.stdout.write(text)
    else:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("server")
    s.add_argument("inventory")
    s.add_argument("-o", "--out")

    c = sub.add_parser("client")
    c.add_argument("inventory")
    c.add_argument("device")
    c.add_argument("-o", "--out")
    c.add_argument("--listen", default="127.0.0.1")
    c.add_argument("--port", type=int, default=2080)
    c.add_argument("--allow-revoked", action="store_true", help="testing only")
    c.add_argument("--mode", choices=CLIENT_MODES, default="proxy",
                   help="proxy: local SOCKS/HTTP port; domain: fake-IP TUN, default route untouched; "
                        "app: full TUN, split by process and domain")

    i = sub.add_parser("ips")
    i.add_argument("inventory")

    d = sub.add_parser("domains", help="client_policy.domain_suffix, one per line (for macOS /etc/resolver)")
    d.add_argument("inventory")

    k = sub.add_parser("check")
    k.add_argument("inventory")

    args = p.parse_args(argv)
    try:
        inv = load(args.inventory)
        if args.cmd == "server":
            write(build_server(inv), args.out)
        elif args.cmd == "client":
            write(build_client(inv, args.device, args.listen, args.port, args.allow_revoked, args.mode), args.out)
        elif args.cmd == "ips":
            sys.stdout.write("".join(ip + "\n" for ip in egress_ips(inv)))
        elif args.cmd == "domains":
            sys.stdout.write("".join(d + "\n" for d in client_policy(inv)["domain_suffix"]))
        elif args.cmd == "check":
            print("inventory ok")
    except InventoryError as e:
        print("inventory error:\n" + str(e), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
