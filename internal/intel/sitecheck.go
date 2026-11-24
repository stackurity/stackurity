package intel

import "github.com/stackurity/stackurity/internal/vendorbuilds"

// SiteCheckProducts are vendor build catalogue products read from NVD even
// when no asset runs them, while website checks are on (the server sets it
// from its configuration): websites name their nginx and PHP versions in
// headers, and a check of a site no customer runs needs their records.
var SiteCheckProducts []string

// siteCheckVendorBuilds is the catalogue products SiteCheckProducts names.
func siteCheckVendorBuilds() []*vendorbuilds.Product {
	cat := vendorbuilds.Default()
	var out []*vendorbuilds.Product
	for _, id := range SiteCheckProducts {
		if p := cat.Product(id); p != nil {
			out = append(out, p)
		}
	}
	return out
}
