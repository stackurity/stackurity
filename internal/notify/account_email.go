package notify

import (
	"fmt"
	"strings"
	"time"
)

// The emails about a person's own account and organisation. They are built
// here, not where they are sent, so the email checks (email_check.go) and
// the previews (tools/emailpreview) render exactly what is sent.

// accountHost is the installation's host name for the text of an email
// ("stackurity.example.com"), from its base URL.
func accountHost(base string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	h, _, _ = strings.Cut(h, "/")
	return h
}

// accountWhere names the installation: "Stackurity (host)".
func accountWhere(base string) string {
	if h := accountHost(base); h != "" {
		return "Stackurity (" + h + ")"
	}
	return "Stackurity"
}

// PasswordResetEmail is the link to choose a new password, sent to email.
// ip is the address the request came from.
func PasswordResetEmail(base, email, link, ip string, at time.Time) Message {
	return Message{Event: "password_reset", Title: "Reset your Stackurity password", At: at,
		Summary: []string{
			"Someone (we hope you) asked to reset the password of the Stackurity account " + email + " on " + accountHost(base) + ".",
			"Choose a new password within 15 minutes. The link works once, and your other sessions will be signed out.",
			"If you did not ask for this, ignore this email: your password stays as it is. The request came from " + ip + ".",
		},
		Link: link, LinkLabel: "Reset password"}
}

// InvitationEmail invites someone to organisation: inviter names who
// invited them, scope what to ("as a member", "to 2 projects").
func InvitationEmail(organisation, inviter, scope, link string, expires, at time.Time) Message {
	return Message{Event: "invitation", Title: "You are invited to " + organisation + " on Stackurity", At: at,
		Summary: []string{
			strings.TrimSpace(fmt.Sprintf("%s invited you to %s %s", inviter, organisation, scope)) + ".",
			"Stackurity lists the software on your servers and code, and tells you which fixes matter.",
			fmt.Sprintf("Open the link to accept. It works once, and until %s.", expires.UTC().Format("2 January 2006 15:04 MST")),
			"If you did not expect this, ignore this email.",
		},
		Link: link, LinkLabel: "Accept invitation"}
}

// EmailCodeEmail is a sign-in code: what is what it is for ("signing
// in", "turning on email codes"), ip where the request came from.
func EmailCodeEmail(base, email, what, code, ip string, at time.Time) Message {
	return Message{Event: "mfa_email_code", Title: "Someone is signing in to Stackurity", At: at, Code: code,
		Summary: []string{
			"Your code for " + what + " to " + accountWhere(base) + " as " + email + ":",
			"It works once, for 10 minutes. Nobody from Stackurity will ask you for it.",
			"If this was not you, someone knows your password: change it now, and tell your administrator. The request came from " + ip + ".",
		}}
}

// EmailCodeSignInEmail tells email that their account signed in with an
// email code.
func EmailCodeSignInEmail(base, email, ip string, at time.Time) Message {
	host := accountHost(base)
	if host == "" {
		host = "Stackurity"
	}
	return Message{Event: "mfa_email_sign_in", Title: "You signed in to Stackurity with an email code", At: at,
		Summary: []string{
			"Your account " + email + " signed in to " + host + " with an email code at " + at.UTC().Format("2 Jan 2006 15:04 UTC") + ", from " + ip + ".",
			"If this was not you, change your password now and tell your administrator.",
			"A passkey or an authenticator app is stronger than email codes: set one up under Your account → Two-factor methods.",
		}}
}

// FactorChangeEmail tells to that their second factors changed ("A
// passkey, “MacBook Touch ID”, was added"). admin names the administrator
// who made the change, for a reset; device is the browser and system
// ("Chrome on macOS").
func FactorChangeEmail(base, to, change, admin, ip, device string, at time.Time) Message {
	who := ""
	if admin != "" {
		who = " by an administrator, " + admin + ","
	}
	from := "From " + ip + ", " + device + "."
	if admin != "" {
		from = "From the administrator's " + ip + ", " + device + "."
	}
	notMe := "If this was not you, someone may have your password: change it now, which signs you out everywhere, then remove anything you do not recognise under Your account → Two-factor methods and tell your administrator."
	m := Message{Event: "mfa_changed", Title: "Your Stackurity two-factor sign-in changed", At: at}
	if base != "" {
		notMe = "If this was not you, someone may have your password: reset it now (that signs you out everywhere), then remove anything you do not recognise under Your account → Two-factor methods and tell your administrator."
		m.Link, m.LinkLabel = strings.TrimRight(base, "/")+"/forgot-password", "Reset password"
	}
	m.Summary = []string{
		change + who + " on your account " + to + " at " + accountWhere(base) + ".",
		"When: " + at.UTC().Format("2 Jan 2006 15:04 UTC") + ". " + from,
		notMe,
		"You get this email whenever your two-factor sign-in changes; it cannot be turned off.",
	}
	return m
}

// AskSpendEmail tells an organisation's administrators that Ask
// Stackurity used level percent (80 or 100) of the month's budget.
func AskSpendEmail(level int, at time.Time) Message {
	title := "Ask Stackurity has used 80% of this month's budget"
	line := "Your organisation has used 80% of its Ask Stackurity budget for this month. When it is used up, questions stop until the 1st."
	if level >= 100 {
		title = "Ask Stackurity's budget for this month is used up"
		line = "Your organisation has used its Ask Stackurity budget for this month. Questions are paused until the 1st."
	}
	return Message{Event: "ask_spend", Title: title, At: at, Summary: []string{line,
		"An administrator can turn Ask Stackurity off under Integrations → AI assistants."}}
}

// InactivePauseEmail warns an organisation's administrators that it will
// be paused on pauseOn because nobody has signed in for a while (the
// plan's inactive pause); last is the second and last warning. base is the
// installation's address.
func InactivePauseEmail(base, org string, pauseOn time.Time, last bool, at time.Time) Message {
	title := "Sign in to keep Stackurity checking " + org
	if last {
		title = "Last reminder: sign in to keep Stackurity checking " + org
	}
	m := Message{Event: "inactive_pause", Title: title, At: at, Summary: []string{
		"Nobody in " + org + " has signed in to Stackurity for a while. On " + pauseOn.UTC().Format("2 January 2006") +
			" it will be paused: nothing new is collected and no notifications are sent until someone signs in.",
		"Everything already there is kept, and signing in at any time resumes it at once.",
		"Any member signing in is enough, also after the pause.",
	}}
	if base != "" {
		m.Link, m.LinkLabel = strings.TrimRight(base, "/")+"/", "Sign in"
	}
	return m
}

// testEmail is a channel's test notification.
func testEmail(at time.Time) Message {
	return Message{Event: "test", Title: "Stackurity test notification", At: at,
		Summary: []string{"This channel is configured correctly."}}
}

// alertConfirmEmail asks an address to confirm it wants an
// organisation's alerts (email sent by Stackurity). confirm is the
// confirmation page, block the page that blocks the address for every
// organisation and blockOneClick its one-click address.
func alertConfirmEmail(organisation, confirm, block, blockOneClick string, at time.Time) Message {
	org := strings.Join(strings.Fields(organisation), " ")
	if r := []rune(org); len(r) > 60 {
		org = string(r[:60]) + "…"
	}
	m := Message{Event: "confirm_email", Title: confirmSubject, At: at,
		Summary: []string{
			fmt.Sprintf("An organisation on Stackurity named %q asked to send security alerts to this address.", org),
			"To receive them, confirm within 7 days.",
			"If you did not expect this, ignore this email: nothing will be sent to you.",
		},
		Link: confirm, LinkLabel: "Confirm email"}
	m.unsubscribe, m.unsubscribeLabel, m.oneClick = block, "Never email me again (from any organisation)", blockOneClick
	return m
}
