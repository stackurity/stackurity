package apps

// The website scanner (internal/webscan) reads the same libraries from a
// live site: from the CDN addresses its pages load and from the banners at
// the top of the scripts it serves.

// WebLibFromURL returns the npm package and exact version a CDN address
// loads, as parseCDNURL.
func WebLibFromURL(raw string) (name, version string, ok bool) { return parseCDNURL(raw) }

// WebLibsFromBanner returns the libraries whose banner is in head, the
// first bytes of the file served at name, as parseBanner. Each entry is
// the npm package and its version.
func WebLibsFromBanner(name string, head []byte) [][2]string {
	if len(head) > bannerSize {
		head = head[:bannerSize]
	}
	return parseBanner(name, head)
}
