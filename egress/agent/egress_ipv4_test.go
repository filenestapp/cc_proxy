package main

import "testing"

func TestMacDefaultInterfaceUsesPhysicalNetwork(t *testing.T) {
	for _, tc := range []struct{ name, route, want string }{
		{"ethernet", "route to: default\ninterface: en0\n", "en0"},
		{"other network service", "  interface: en10\n", "en10"},
		{"vpn", "interface: utun4\n", ""},
		{"bridge", "interface: bridge0\n", ""},
		{"malformed name", "interface: enX\n", ""},
		{"no route", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := macDefaultInterface(tc.route); got != tc.want {
				t.Fatalf("got %q, expected %q", got, tc.want)
			}
		})
	}
}
