package main

import (
	"errors"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

const marketingOrigin = "https://aifree.sg"

// marketingSession gives the homepage just enough information to render its account link.
// It neither returns customer data nor renews or shares the account host's session cookie.
func (a *api) marketingSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Origin")
	if r.Header.Get("Origin") != marketingOrigin {
		sendResponse(w, response{status: http.StatusForbidden, body: object{"error": "origin not allowed"}})
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", marketingOrigin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	var signedIn bool
	if token := customerCookieValue(r); token != "" {
		_, err := a.store.customerSession(r.Context(), token)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("read marketing session: %v", err)
			sendResponse(w, response{status: http.StatusServiceUnavailable, body: object{"error": "session unavailable"}})
			return
		}
		signedIn = err == nil
	}
	sendResponse(w, response{status: http.StatusOK, body: object{"signed_in": signedIn}})
}
