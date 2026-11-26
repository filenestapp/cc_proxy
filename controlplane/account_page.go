package main

import (
	"bytes"
	_ "embed"
	"net/http"
)

//go:embed account.html
var accountTemplate []byte

//go:embed desktop_downloads.js
var desktopDownloadsScript []byte

// Keep the account page self-contained while using the same chooser as the marketing site.
var accountPage = bytes.Replace(accountTemplate, []byte("/* embedded-desktop-downloads */"), desktopDownloadsScript, 1)

// accountPagePaths are the user-center URLs. The page routes on the client side,
// reading ?token= on verify/reset and ?plan= on checkout (linked from the marketing site).
var accountPagePaths = []string{
	"/account", "/account/{$}", "/account/login", "/account/register", "/account/verify",
	"/account/reset", "/account/forgot", "/account/checkout",
}

func (a *api) accountPageRoutes() {
	for _, path := range accountPagePaths {
		a.mux.HandleFunc("GET "+path, serveAccountPage)
	}
	a.mux.HandleFunc("GET /v1/account/session", a.marketingSession)
}

// serveAccountPage sends the page with no-referrer: verify and reset URLs carry a
// one-time token, which must not leak through the Referer of any request or link.
func serveAccountPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; "+
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://downloads.aifree.sg; frame-ancestors 'none'")
	sendResponse(w, response{status: 200, body: accountPage, contentType: "text/html; charset=utf-8"})
}
