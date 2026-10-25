//go:build !ee

package notify

import (
	"context"

	"github.com/stackurity/stackurity/internal/store"
)

// escalate is part of Stackurity Pro; the Community build does not escalate
// overdue incidents (see docs/design/open-core.md).
func (d *Dispatcher) escalate(ctx context.Context, routes []store.Route) error { return nil }
