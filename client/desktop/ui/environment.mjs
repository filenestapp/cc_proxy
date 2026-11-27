const errors = {
  dns: "environment_dns_error",
  timeout: "environment_timeout",
  network: "environment_network_error",
  tls: "environment_tls_error",
  no_response: "environment_not_returned",
  http: "environment_http_error",
  invalid_response: "environment_invalid_response",
};

const stunVerdicts = {
  exit: "environment_stun_exit",
  leak: "environment_stun_leak",
  no_answer: "environment_stun_no_answer",
};

const findings = {
  exits: "environment_route_comparison",
  ipv6: "IPv6",
  udp: "environment_udp",
  dns: "environment_dns",
  tz: "environment_time_zone",
  lang: "environment_system_language",
  tls: "environment_tls_version",
  rtt: "environment_rtt",
  "proxy-path": "environment_proxy_path",
  "tcp-os": "TCP",
};

const list = (value) => Array.isArray(value) ? value : [];
const present = (value) => typeof value === "string" && value.length > 0;
const milliseconds = (value) => Number.isFinite(value) ? value.toFixed(1) + " ms" : "";
const family = (value) => value.includes(":") ? "IPv6" : "IPv4";
const join = (values) => values.filter(present).join(" · ");
const literal = (host) => /^[0-9.]+$/.test(host) || host.includes(":");

function element(tag, classes, value) {
  const node = document.createElement(tag);
  if (classes) node.className = classes;
  if (value !== undefined) node.textContent = String(value);
  return node;
}

function facts(entries) {
  const dl = element("dl", "environment-facts");
  for (const [label, value] of entries) {
    if (value !== null && value !== undefined && value !== "") {
      dl.append(element("dt", "", label), element("dd", "", value));
    }
  }
  return dl;
}

function details(label, content, options = {}) {
  const disclosure = element("details", "environment-section");
  disclosure.open = options.open ?? false;
  const summary = element("summary", "", label);
  if (options.count !== undefined) summary.append(element("span", "environment-count", options.count));
  disclosure.append(summary, content);
  return disclosure;
}

function rowList(rows) {
  const ul = element("ul", "environment-list");
  for (const row of rows) {
    const item = element("li", "environment-row");
    item.append(
      element("strong", "environment-key", row.label),
      element(row.code ? "code" : "span", "environment-value", row.value),
    );
    if (row.note) {
      const note = element("span", "environment-secondary", row.note);
      if (row.lang) note.lang = row.lang;
      item.append(note);
    }
    ul.append(item);
  }
  return ul;
}

function probeFailure(row, t) {
  if (typeof row.status === "number" && row.status !== 200) return "HTTP " + row.status;
  return t(errors[row.error] ?? "environment_not_returned");
}

function exitRows(exits, t) {
  return exits.map((exit) => ({
    label: exit.host,
    value: exit.ip ?? probeFailure(exit, t),
    code: Boolean(exit.ip),
    note: join([
      exit.via === "proxy" ? t("environment_proxy_path") : "",
      exit.family === 6 ? "IPv6" : "",
      exit.cc, exit.colo, milliseconds(exit.ms),
    ]),
  }));
}

function networkRows(probes, t) {
  return probes.map((probe) => {
    const mode = probe.method === "system" ? t("environment_system_dns")
      : probe.method === "google-ecs" ? t("environment_ecs")
        : probe.method === "stun" ? "STUN" : "";
    const verdict = probe.method === "stun" && Object.hasOwn(stunVerdicts, probe.verdict)
      ? t(stunVerdicts[probe.verdict]) : "";
    return {
      label: join([probe.server, mode]),
      value: probe.ip ?? (verdict || (probe.fake ? t("environment_fake_ip") : probe.ecs ?? probeFailure(probe, t))),
      code: Boolean(probe.ip),
      note: join([
        probe.family ? "IPv" + probe.family : "",
        probe.ip ? verdict : "",
        verdict && !probe.ip && probe.error ? probeFailure(probe, t) : "",
        probe.ip && probe.ecs ? t("environment_ecs") + " " + probe.ecs : "",
        milliseconds(probe.ms),
      ]),
    };
  });
}

function hasStunLeak(report) {
  return list(report?.udp).some((probe) => probe.method === "stun" && probe.verdict === "leak");
}

function compare(exits) {
  const ipv4 = [];
  const ipv6 = [];
  for (const exit of exits) {
    if (!exit.ip || !exit.host || literal(exit.host)) continue;
    (family(exit.ip) === "IPv4" ? ipv4 : ipv6).push(exit.ip);
  }
  if ([ipv4, ipv6].some((addresses) => new Set(addresses).size > 1)) return "environment_different_exits";
  return [ipv4, ipv6].some((addresses) => addresses.length > 1) ? "environment_same_exit" : "environment_limited";
}

function quality(report, t) {
  const level = report.server?.groups?.ip?.level;
  return t(["low", "some", "elevated", "high"].includes(level) ? "environment_" + level : "environment_unavailable");
}

function resultSummary(report, t) {
  const ip = report.server?.ip;
  const first = list(report.exits).find((value) => value.host === "claude.ai" && value.ip)
    ?? list(report.exits).find((value) => value.ip);
  const providerAddress = ip?.ip && !ip.private ? ip.ip : null;
  const observed = providerAddress ?? first?.ip;
  const meta = providerAddress
    ? join([report.server.base_src || "netcheck.wenbo.io", ip?.country, ip?.asn ? "AS" + ip.asn : "", ip?.org])
    : join([first?.host, first?.cc]);
  const card = element("div", "environment-summary");
  card.append(element("h2", "", t("environment_observed_exit")));
  card.append(element(observed ? "code" : "p", observed ? "environment-address" : "environment-meta",
    observed ?? t("environment_not_returned")));
  if (meta) card.append(element("p", "environment-meta", meta));
  card.append(facts([
    [t("environment_route_comparison"), t(compare(list(report.exits)))],
    [t("environment_quality"), quality(report, t)],
  ]));
  return card;
}

function findingRows(server, t) {
  return list(server?.signals)
    .filter((signal) => ["strong", "medium", "weak"].includes(signal?.level))
    .map((signal) => {
      const label = Object.hasOwn(findings, signal.key) ? findings[signal.key] : null;
      const localized = label?.startsWith("environment_") ? t(label) : label;
      return {
        label: localized ?? signal.title ?? t("environment_observation"),
        value: t(signal.level === "strong" ? "environment_marked" : "environment_review"),
        note: signal.obs || signal.short || signal.detail,
        lang: "zh-Hans",
      };
    });
}

function reputationRows(server, t) {
  return list(server?.raw?.reputation ?? server?.reputation).map((row) => {
    const status = row?.status;
    const fields = row?.dims;
    const indicators = join([
      fields?.vpn === true ? "VPN" : "", fields?.proxy === true ? "Proxy" : "",
      fields?.tor === true ? "Tor" : "", typeof fields?.type === "string" ? fields.type : "",
    ]);
    const rating = status === "ok" ? (fields?.risk ?? t("environment_info"))
      : t(status === "quota" ? "environment_source_quota" : "environment_source_disabled");
    return { label: row?.label || row?.provider || "netcheck.wenbo.io", value: String(rating), note: indicators };
  });
}

function localDetails(local, t) {
  const route = local?.route;
  const system = Object.entries(local?.system_proxy ?? {}).map(([key, value]) => key.toUpperCase() + " " + value);
  const tunnels = list(local?.tunnels).map((tunnel) => join([tunnel.name, tunnel.mtu ? "MTU " + tunnel.mtu : "", list(tunnel.addresses).join(", ")]));
  return facts([
    [t("environment_os"), local?.os_version],
    [t("environment_arch"), local?.architecture],
    [t("environment_time_zone"), local?.timezone || (Number.isFinite(local?.utc_offset_minutes) ? "UTC " + local.utc_offset_minutes + " min" : "")],
    [t("environment_system_language"), list(local?.languages).join(", ")],
    [t("environment_route"), join([route?.interface, route?.mtu ? "MTU " + route.mtu : ""])],
    [t("environment_gateway"), route?.gateway],
    [t("environment_tunnels"), tunnels.join(", ")],
    [t("environment_vpn_services"), list(local?.vpn_services).join(", ")],
    [t("environment_tailscale"), local?.tailscale_exit],
    [t("environment_proxy_path"), system.join(", ")],
    [t("environment_proxy_env"), list(local?.proxy_environment).join(", ")],
    [t("environment_dns_servers"), list(local?.dns_servers).join(", ")],
  ]);
}

function transportDetails(report, t) {
  const data = report.transport ?? {};
  const rtt = report.server?.rtt ?? {};
  return facts([
    [t("environment_service_ip"), data.peer],
    [t("environment_tcp_connect"), milliseconds(data.connect_ms)],
    [t("environment_tls_handshake"), milliseconds(data.tls_ms) || (data.tls_error ? probeFailure({ error: data.tls_error }, t) : "")],
    [t("environment_tls_version"), data.tls_version],
    [t("environment_tls_issuer"), data.certificate_issuer],
    [t("environment_rtt"), milliseconds(rtt.app_median)],
    [t("environment_samples"), list(data.pings).length],
  ]);
}

function renderReport(report, t) {
  const nodes = [resultSummary(report, t)];
  const exits = exitRows(list(report.exits), t);
  const suggested = findingRows(report.server, t);
  const reputation = reputationRows(report.server, t);
  const comparison = list(report.resolutions).map((entry) => ({
    label: entry.host,
    value: list(entry.system).join(", ") || t("environment_not_returned"),
    code: Boolean(list(entry.system).length),
    note: list(entry.public).length ? t("environment_public_dns") + " " + entry.public.join(", ") : "",
  }));
  if (suggested.length) nodes.push(details(t("environment_findings"), rowList(suggested), { count: suggested.length, open: true }));
  nodes.push(details(t("environment_exits"), rowList(exits), { count: exits.length, open: !suggested.length }));
  nodes.push(details(t("environment_dns"), rowList(networkRows(list(report.dns), t))));
  nodes.push(details(t("environment_udp"), rowList(networkRows(list(report.udp), t)), { open: hasStunLeak(report) }));
  if (reputation.length) nodes.push(details(t("environment_quality"), rowList(reputation)));
  if (comparison.length) nodes.push(details(t("environment_resolutions"), rowList(comparison)));
  nodes.push(details(t("environment_local"), localDetails(report.local, t)));
  nodes.push(details(t("environment_transport"), transportDetails(report, t)));
  nodes.push(details(t("environment_raw"), element("pre", "environment-json", JSON.stringify(report, null, 2))));
  return nodes;
}

export function createEnvironmentPage({ invoke, translate, onNavigate }) {
  const $ = (id) => document.getElementById(id);
  const page = $("environment-page");
  const open = $("environment-open");
  const retry = $("environment-run");
  const output = $("environment-results");
  const status = $("environment-status");
  let active = false;
  let checking = false;
  let report;
  let error;

  function render() {
    retry.disabled = checking;
    output.setAttribute("aria-busy", String(checking));
    const partial = report?.incomplete || report?.server_error;
    const leak = hasStunLeak(report);
    status.dataset.tone = error ? "error" : (leak || partial) ? "warning" : "";
    let key;
    if (checking) key = "environment_running";
    else if (error) key = error;
    else if (leak) key = "environment_stun_leak_warning";
    else if (report?.incomplete) key = "environment_incomplete";
    else if (report) key = partial ? "environment_partial" : "environment_complete";
    status.textContent = key ? translate(key) : "";
    output.replaceChildren(...(report ? renderReport(report, translate) : []));
  }

  async function check() {
    if (checking) return;
    checking = true;
    report = null;
    error = null;
    render();
    try {
      const result = await invoke("run_environment_check");
      if (!Array.isArray(result?.exits)) throw Error("Invalid environment report");
      report = result;
    } catch (reason) {
      error = reason === "already_running" ? "environment_already_running" : "environment_failed";
    } finally {
      checking = false;
      render();
    }
  }

  function close() {
    active = false;
    page.hidden = true;
    onNavigate();
    open.focus();
  }

  open.addEventListener("click", () => {
    active = true;
    page.hidden = false;
    onNavigate();
    $("environment-title").focus();
    if (!checking && !report && !error) void check();
  });
  retry.addEventListener("click", check);
  $("environment-back").addEventListener("click", close);
  page.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !event.defaultPrevented) close();
  });
  return { isOpen: () => active, render };
}
