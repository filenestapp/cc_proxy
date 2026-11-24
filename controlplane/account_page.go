package main

import (
	_ "embed"
	"net/http"
)

//go:embed account.html
var accountPage []byte

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
}

// serveAccountPage sends the page with no-referrer: verify and reset URLs carry a
// one-time token, which must not leak through the Referer of any request or link.
func serveAccountPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	sendResponse(w, response{status: 200, body: accountPage, contentType: "text/html; charset=utf-8"})
}
