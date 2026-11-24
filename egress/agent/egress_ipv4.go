package main

import (
	"context"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Discover the IPv4 on the Mac's default network interface. A tunnel or bridge
// needs a manually selected address instead of an automatically seeded pool.
func detectMacEgressIPv4() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	route, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "-inet", "default").Output()
	if err != nil {
		return ""
	}
	iface := macDefaultInterface(string(route))
	if iface == "" {
		return ""
	}
	output, err := exec.CommandContext(ctx, "/usr/sbin/ipconfig", "getifaddr", iface).Output()
	if err != nil {
		return ""
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(output)))
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
		return ""
	}
	return address.String()
}

func macDefaultInterface(route string) string {
	for _, line := range strings.Split(route, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "interface:" {
			continue
		}
		iface := fields[1]
		number, ok := strings.CutPrefix(iface, "en")
		if ok && number != "" && strings.Trim(number, "0123456789") == "" {
			return iface
		}
		return ""
	}
	return ""
}
