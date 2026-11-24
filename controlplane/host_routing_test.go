package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostRoutingSeparatesCustomerAndControlPlaneRoutes(t *testing.T) {
	h := newAPI(nil, testAdminToken, "", nil)

	for _, tc := range []struct {
		name, host, method, path string
		want                     int
	}{
		{"control plane console", controlPlaneHost, http.MethodGet, "/console", http.StatusOK},
		{"legacy control plane console", legacyControlPlaneHost, http.MethodGet, "/console", http.StatusOK},
		{"customer host hides console", customerHost, http.MethodGet, "/console", http.StatusNotFound},
		{"control plane hides customer API", controlPlaneHost, http.MethodPost, "/v1/account/login", http.StatusNotFound},
		{"customer host serves customer API", customerHost + ":8443", http.MethodPost, "/v1/account/login", http.StatusBadRequest},
		{"unknown host retains console", "localhost:8443", http.MethodGet, "/console", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(nil))
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("%s %s on %s: got %d, want %d", tc.method, tc.path, tc.host, rec.Code, tc.want)
			}
		})
	}
}
