//go:build !ee

package notify

import (
	"context"
)

// escalate is part of Stackurity Pro; the Community build does not escalate
// overdue incidents (see docs/design/open-core.md).
func (d *Dispatcher) escalate(ctx context.Context) (map[int64]int, error) { return nil, nil }

// overdueOn: summaries list overdue issues in the licensed build only.
func (d *Dispatcher) overdueOn(ctx context.Context) bool { return false }
