package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"
)

const probeUserAgent = "Mozilla/5.0 (compatible; egress-health/0.1)"

// httpProbe GETs target with the connection bound to sourceIP, like controlplane/probes.py http_probe. Latency is
// time to response headers. ok means 2xx/3xx (redirects are not followed); 403 and 429, the usual signs that a
// target has started to block an IP, count as failures.
func httpProbe(target, sourceIP string, timeout time.Duration) ProbeResult {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		scheme := ""
		if u != nil {
			scheme = u.Scheme
		}
		return ProbeResult{Detail: "unsupported scheme " + scheme}
	}
	dialer := &net.Dialer{Timeout: timeout}
	if ip := net.ParseIP(sourceIP); ip != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return ProbeResult{Detail: fmt.Sprintf("request: %v", err)}
	}
	req.Header.Set("User-Agent", probeUserAgent)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{Detail: fmt.Sprintf("%T: %v", err, err)}
	}
	latency := math.Round(float64(time.Since(start).Microseconds())/100) / 10
	io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
	resp.Body.Close()
	return ProbeResult{OK: resp.StatusCode >= 200 && resp.StatusCode < 400, LatencyMS: &latency,
		Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}
