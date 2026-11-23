package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Egress IP management (--iface, Linux only), the counterpart of egress/deploy/ips.sh with one difference: the
// agent only touches addresses it added itself. Every address it adds is recorded in owned-ips.txt next to the IP
// list ("IP IFACE" per line). An address already on the interface is left as it is, never replaced, and "down"
// removes only recorded addresses, so an address an administrator configured survives an uninstall.

var ipsSupported = runtime.GOOS == "linux"

// addrTool reads and changes the IPv4 addresses of an interface. Replaced in tests.
type addrTool interface {
	list(iface string) (map[string]bool, error)
	add(ip, iface string) error
	del(ip, iface string) error
}

type ipCommand struct{}

func (ipCommand) list(iface string) (map[string]bool, error) {
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", iface).Output()
	if err != nil {
		return nil, fmt.Errorf("ip addr show dev %s: %v", iface, err)
	}
	present := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				present[strings.SplitN(f[i+1], "/", 2)[0]] = true
			}
		}
	}
	return present, nil
}

func (ipCommand) add(ip, iface string) error { return runIP("add", ip, iface) }
func (ipCommand) del(ip, iface string) error { return runIP("del", ip, iface) }

func runIP(op, ip, iface string) error {
	out, err := exec.Command("ip", "addr", op, ip+"/32", "dev", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr %s %s/32 dev %s: %v: %s", op, ip, iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

var ipTool addrTool = ipCommand{}

// readIPs reads one IPv4 address per line (output of /agent/ips); blank lines and # comments are skipped.
func readIPs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("%s: not an IPv4 address: %q", path, line)
		}
		out = append(out, ip.To4().String())
	}
	return out, sc.Err()
}

func ownedPath(ipsFile string) string { return filepath.Join(filepath.Dir(ipsFile), "owned-ips.txt") }

// readOwned: IP -> interface for every address this agent added.
func readOwned(path string) (map[string]string, error) {
	owned := map[string]string{}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return owned, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && net.ParseIP(f[0]) != nil {
			owned[f[0]] = f[1]
		}
	}
	return owned, nil
}

func writeOwned(path string, owned map[string]string) error {
	ips := make([]string, 0, len(owned))
	for ip := range owned {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var b strings.Builder
	b.WriteString("# Egress IPs ccproxy-exit-agent added (IP IFACE); only these are ever removed.\n")
	for _, ip := range ips {
		fmt.Fprintf(&b, "%s %s\n", ip, owned[ip])
	}
	tmp, err := writeTemp(filepath.Dir(path), []byte(b.String()))
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ipsUp adds every address in the list that iface does not have yet, recording each one it adds.
func ipsUp(iface, path string, logf func(string, ...any)) error {
	if !ipsSupported {
		return fmt.Errorf("egress IP management (--iface) is Linux-only; elsewhere the host's existing address is used")
	}
	return ipsUpWith(ipTool, iface, path, logf)
}

func ipsUpWith(tool addrTool, iface, path string, logf func(string, ...any)) error {
	want, err := readIPs(path)
	if err != nil {
		return err
	}
	recordPath := ownedPath(path)
	owned, err := readOwned(recordPath)
	if err != nil {
		return err
	}
	present, err := tool.list(iface)
	if err != nil {
		return err
	}
	added, foreign := 0, []string{}
	for _, ip := range want {
		if present[ip] {
			if _, ours := owned[ip]; !ours {
				foreign = append(foreign, ip)
			}
			continue
		}
		if err := tool.add(ip, iface); err != nil {
			return err
		}
		owned[ip] = iface
		if err := writeOwned(recordPath, owned); err != nil { // recorded before the next change
			return err
		}
		added++
	}
	if len(foreign) > 0 {
		logf("left alone (already on %s, not added by this agent, never removed by it): %s", iface, strings.Join(foreign, " "))
	}
	logf("up: %d address(es) in the list, %d added to %s", len(want), added, iface)
	return nil
}

// ipsDown removes only the addresses this agent recorded as added on iface. Addresses in the list that it did
// not add are named and kept.
func ipsDown(iface, path string, logf func(string, ...any)) error {
	return ipsDownWith(ipTool, iface, path, logf)
}

func ipsDownWith(tool addrTool, iface, path string, logf func(string, ...any)) error {
	recordPath := ownedPath(path)
	owned, err := readOwned(recordPath)
	if err != nil {
		return err
	}
	present, err := tool.list(iface)
	if err != nil {
		return err
	}
	removed, removedNow := 0, map[string]bool{}
	for ip, onIface := range owned {
		if onIface != iface {
			continue
		}
		if present[ip] {
			if err := tool.del(ip, iface); err != nil {
				return err
			}
			removed++
		}
		removedNow[ip] = true
		delete(owned, ip)
		if err := writeOwned(recordPath, owned); err != nil {
			return err
		}
	}
	if listed, err := readIPs(path); err == nil {
		kept := []string{}
		for _, ip := range listed {
			if _, ours := owned[ip]; present[ip] && !ours && !removedNow[ip] {
				kept = append(kept, ip)
			}
		}
		if len(kept) > 0 {
			logf("kept (not added by this agent): %s", strings.Join(kept, " "))
		}
	}
	logf("down: removed %d address(es) this agent had added to %s", removed, iface)
	return nil
}
