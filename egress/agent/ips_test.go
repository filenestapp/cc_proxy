package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fakeIP is an interface's address table, like `ip addr` would change it.
type fakeIP struct {
	addrs map[string]bool
	calls []string
}

func (f *fakeIP) list(string) (map[string]bool, error) {
	out := map[string]bool{}
	for k, v := range f.addrs {
		out[k] = v
	}
	return out, nil
}
func (f *fakeIP) add(ip, iface string) error {
	f.calls = append(f.calls, "add "+ip+" "+iface)
	f.addrs[ip] = true
	return nil
}
func (f *fakeIP) del(ip, iface string) error {
	f.calls = append(f.calls, "del "+ip+" "+iface)
	delete(f.addrs, ip)
	return nil
}

func (f *fakeIP) have() string {
	var ips []string
	for ip := range f.addrs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return strings.Join(ips, ",")
}

// Regression: an address that was on the interface before the agent (192.0.2.20) must survive up and down, even
// when the inventory lists it; only the address the agent added (192.0.2.21) is removed.
func TestIPsDownRemovesOnlyAddressesTheAgentAdded(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "ips.txt")
	os.WriteFile(list, []byte("192.0.2.20\n192.0.2.21\n"), 0o600)
	tool := &fakeIP{addrs: map[string]bool{"192.0.2.20": true, "198.51.100.9": true}}
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, f) }

	if err := ipsUpWith(tool, "eth0", list, logf); err != nil {
		t.Fatal(err)
	}
	if strings.Join(tool.calls, ";") != "add 192.0.2.21 eth0" {
		t.Fatalf("up must neither replace nor re-add the existing address: %v", tool.calls)
	}
	owned, _ := os.ReadFile(filepath.Join(dir, "owned-ips.txt"))
	if !strings.Contains(string(owned), "192.0.2.21 eth0") || strings.Contains(string(owned), "192.0.2.20") {
		t.Fatalf("ownership record: %s", owned)
	}

	if err := ipsUpWith(tool, "eth0", list, logf); err != nil { // a second boot / sync: nothing to do
		t.Fatal(err)
	}
	if len(tool.calls) != 1 {
		t.Fatalf("repeated up changed the interface: %v", tool.calls)
	}

	if err := ipsDownWith(tool, "eth0", list, logf); err != nil {
		t.Fatal(err)
	}
	if got := tool.have(); got != "192.0.2.20,198.51.100.9" {
		t.Fatalf("after down the interface has %s; the pre-existing addresses must stay", got)
	}
	if strings.Join(tool.calls, ";") != "add 192.0.2.21 eth0;del 192.0.2.21 eth0" {
		t.Fatalf("calls %v", tool.calls)
	}
	if owned, _ := readOwned(filepath.Join(dir, "owned-ips.txt")); len(owned) != 0 {
		t.Fatalf("record not cleared: %v", owned)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "kept (not added by this agent)") {
		t.Fatalf("the kept address is not reported: %v", logs)
	}
}

// An address the agent added and someone removed meanwhile is just forgotten; another interface's record stays.
func TestIPsDownForgetsVanishedAddressesAndKeepsOtherInterfaces(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "ips.txt")
	os.WriteFile(list, []byte("192.0.2.30\n"), 0o600)
	writeOwned(ownedPath(list), map[string]string{"192.0.2.30": "eth0", "192.0.2.31": "eth1"})
	tool := &fakeIP{addrs: map[string]bool{}}
	if err := ipsDownWith(tool, "eth0", list, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if len(tool.calls) != 0 {
		t.Fatalf("removed an address that was not there: %v", tool.calls)
	}
	owned, _ := readOwned(ownedPath(list))
	if len(owned) != 1 || owned["192.0.2.31"] != "eth1" {
		t.Fatalf("record %v", owned)
	}
}
