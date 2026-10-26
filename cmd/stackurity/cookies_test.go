package main

import "testing"

func TestCookieRisk(t *testing.T) {
	for _, c := range []struct {
		secure       bool
		base, listen string
		risky        bool
	}{
		// Secure cookies are never a risk.
		{true, "", ":8080", false},
		{true, "http://203.0.113.5:8080", ":8080", false},
		// Declared local evaluations.
		{false, "http://localhost:8080", ":8080", false},
		{false, "http://127.0.0.1:8080/", "0.0.0.0:8080", false},
		{false, "http://[::1]:8080", ":8080", false},
		{false, "http://stackurity.localhost", ":8080", false},
		{false, "", "127.0.0.1:8080", false},
		{false, "", "localhost:8080", false},
		{false, "", "[::1]:8080", false},
		// Everything else.
		{false, "", ":8080", true},
		{false, "", "0.0.0.0:8080", true},
		{false, "", "192.168.1.10:8080", true},
		{false, "https://stackurity.example.com", ":8080", true},
		{false, "https://localhost:8443", "127.0.0.1:8080", true},
		{false, "http://stackurity.example.com", "127.0.0.1:8080", true},
		{false, "http://192.168.1.10:8080", ":8080", true},
		{false, "http://localhost.example.com", ":8080", true},
		{false, "://bad", "127.0.0.1:8080", true},
	} {
		got := cookieRisk(c.secure, c.base, c.listen)
		if (got != "") != c.risky {
			t.Errorf("cookieRisk(%v, %q, %q) = %q, want risky=%v", c.secure, c.base, c.listen, got, c.risky)
		}
	}
}
