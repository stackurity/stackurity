//go:build !(ee && cloud)

package main

// wantTrustBadgeCloud: the Community and licensed self-hosted builds never
// run the trust badge.
const wantTrustBadgeCloud = false
