package main

import _ "embed"

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
		a.bind("GET "+path, "", "", a.accountPage)
	}
}

func (a *api) accountPage(_ *apiRequest) (response, error) {
	return response{status: 200, body: accountPage, contentType: "text/html; charset=utf-8"}, nil
}
