package api

import "strings"

// The Permissions-Policy header (docs/security-audit.md, "Browser and
// API"): the browser features the dashboard never uses are turned off for
// every page and any frame it embeds, so a script that got in (or a
// widget) cannot ask for the camera, the microphone or the location.
//
// Left at the browser's default (this origin only), because something
// uses them:
//   - payment: Razorpay Checkout on the payment page (below);
//   - publickey-credentials-get and -create: passkeys and security keys
//     (WebAuthn) for this origin;
//   - clipboard-write: the dashboard's copy buttons;
//   - fullscreen.
//
// Features a browser does not know are ignored by it (Chrome logs a console
// warning), so only features browsers implement are listed.
var deniedFeatures = []string{
	"accelerometer", "autoplay", "bluetooth", "browsing-topics", "camera", "display-capture",
	"encrypted-media", "gamepad", "geolocation", "gyroscope", "hid", "idle-detection",
	"local-fonts", "magnetometer", "microphone", "midi", "otp-credentials", "picture-in-picture", "screen-wake-lock",
	"serial", "usb", "web-share", "xr-spatial-tracking",
}

// checkoutOrigins are the origins of Razorpay Checkout's frame.
const checkoutOrigins = `"https://api.razorpay.com" "https://checkout.razorpay.com"`

// checkoutFeatures are what checkout.js asks for its frame (the allow
// attribute of the iframe it creates: otp-credentials, payment,
// clipboard-write, publickey-credentials-get/-create, web-share and camera,
// for the card OTP, payment apps, saved cards and scanning a card or QR
// code). On the payment page they are delegated to Razorpay's origins only.
var checkoutFeatures = map[string]bool{"camera": true, "otp-credentials": true, "web-share": true}

func permissionsPolicyValue(checkout bool) string {
	parts := make([]string, 0, len(deniedFeatures)+3)
	for _, f := range deniedFeatures {
		if checkout && checkoutFeatures[f] {
			parts = append(parts, f+"=(self "+checkoutOrigins+")")
			continue
		}
		parts = append(parts, f+"=()")
	}
	if checkout {
		parts = append(parts, "payment=(self "+checkoutOrigins+")",
			"publickey-credentials-get=(self "+checkoutOrigins+")", "publickey-credentials-create=(self "+checkoutOrigins+")")
	}
	return strings.Join(parts, ", ")
}

var (
	permissionsPolicy         = permissionsPolicyValue(false)
	checkoutPermissionsPolicy = permissionsPolicyValue(true)
)

// permissionsPolicyFor is the header for a request path: the payment page
// of the hosted edition (/billing/pay/…) lets Razorpay Checkout's frame use
// what it needs; every other page gets the strict policy.
func permissionsPolicyFor(path string) string {
	if strings.HasPrefix(path, "/billing/pay/") {
		return checkoutPermissionsPolicy
	}
	return permissionsPolicy
}
