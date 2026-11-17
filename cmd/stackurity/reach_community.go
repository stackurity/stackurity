//go:build !ee

package main

import (
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
)

// setPolicySteps adds the risk policy steps a paid plan brings. Community
// has none: it shows each finding's reachability and evidence but never
// changes a priority because of it (docs/reachability.md). The licensed
// build replaces this file.
func setPolicySteps(st *store.Store, gate *license.Gate) {}
