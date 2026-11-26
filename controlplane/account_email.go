package main

import (
	"context"
	_ "embed"
	"html/template"
	"log"
	"net/url"
	"strings"
)

//go:embed account_email.html
var accountEmailHTML string

var accountEmailTemplate = template.Must(template.New("account email").Parse(accountEmailHTML))

type accountEmail struct {
	Subject  string
	Heading  string
	Intro    string
	Action   string
	Expiry   string
	Note     string
	LinkPath string
}

var verificationEmail = accountEmail{
	Subject:  "Verify your aifree email",
	Heading:  "Verify your email address",
	Intro:    "Confirm this email address to finish setting up your aifree account.",
	Action:   "Verify email",
	Expiry:   "This link expires in 24 hours.",
	Note:     "If you didn't sign up for aifree, you can ignore this email.",
	LinkPath: "/verify",
}

var passwordResetEmail = accountEmail{
	Subject:  "Reset your aifree password",
	Heading:  "Reset your password",
	Intro:    "You requested a password reset. Use the link below to choose a new password for your aifree account.",
	Action:   "Reset password",
	Expiry:   "This link expires in 1 hour.",
	Note:     "If you didn't request a password reset, you can ignore this email.",
	LinkPath: "/reset",
}

func (email accountEmail) render(token string) (mailMessage, error) {
	link := accountURL + email.LinkPath + "?" + url.Values{"token": {token}}.Encode()
	data := struct {
		accountEmail
		Link string
	}{email, link}
	var html strings.Builder
	if err := accountEmailTemplate.Execute(&html, data); err != nil {
		return mailMessage{}, err
	}
	return mailMessage{
		subject: email.Subject,
		html:    html.String(),
		text:    strings.Join([]string{email.Heading, email.Intro, email.Action + "\n" + link, email.Expiry, email.Note}, "\n\n"),
	}, nil
}

func (a *api) sendAccountEmail(to, token string, email accountEmail) {
	if token == "" {
		return
	}
	if a.mail == nil {
		log.Printf("send account email %q: cloud-mail is not configured", email.Subject)
		return
	}
	go func() {
		message, err := email.render(token)
		if err != nil {
			log.Printf("render account email %q: %v", email.Subject, err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), mailSendTimeout)
		defer cancel()
		if err := a.mail.send(ctx, to, message); err != nil {
			log.Printf("send account email %q: %v", email.Subject, err)
		}
	}()
}
