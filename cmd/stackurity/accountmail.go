package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/notify"
)

// accountMailer is how the server emails people about their own account
// (password reset links): the platform's mail where an edition provides it
// (Stackurity Cloud), otherwise the operator's mail server from
// STACKURITY_SMTP_*. Nil when neither is set: administrators then reset
// passwords by hand. The operator chose this server, so it may be on a
// private address (a local relay); workspaces' own mail servers are still
// checked against their network policy.
func accountMailer(d *notify.Dispatcher, log *slog.Logger) (notify.Mailer, error) {
	if d != nil && d.PlatformMail != nil {
		return d.PlatformMail, nil
	}
	host := strings.TrimSpace(os.Getenv("STACKURITY_SMTP_HOST"))
	if host == "" {
		return nil, nil
	}
	from := strings.TrimSpace(os.Getenv("STACKURITY_SMTP_FROM"))
	if from == "" {
		return nil, fmt.Errorf("STACKURITY_SMTP_FROM is required with STACKURITY_SMTP_HOST")
	}
	port := 587
	if v := os.Getenv("STACKURITY_SMTP_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("STACKURITY_SMTP_PORT must be a port number")
		}
		port = p
	}
	tls := strings.TrimSpace(os.Getenv("STACKURITY_SMTP_TLS"))
	switch tls {
	case "", "starttls", "tls", "none":
	default:
		return nil, fmt.Errorf("STACKURITY_SMTP_TLS must be starttls, tls or none")
	}
	password := os.Getenv("STACKURITY_SMTP_PASSWORD")
	if f := os.Getenv("STACKURITY_SMTP_PASSWORD_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read STACKURITY_SMTP_PASSWORD_FILE: %w", err)
		}
		password = strings.TrimSpace(string(b))
	}
	sender := notify.NewSender(false)
	sender.Dial = (&net.Dialer{}).DialContext
	log.Info("account email enabled (password reset links)", "smtp_host", host, "from", from)
	return &notify.SMTPMailer{Sender: sender, Password: password, Config: notify.ChannelConfig{
		Host: host, Port: port, Username: os.Getenv("STACKURITY_SMTP_USERNAME"), From: from, TLS: tls}}, nil
}
