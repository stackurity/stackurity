package store

import (
	"context"

	"github.com/stackurity/stackurity/internal/model"
)

// SelftestScheme marks the throwaway asset that `stackurity selftest`
// creates (cmd/stackurity/selftest.go). An asset whose only identifiers have this
// scheme is a selftest asset: it is never announced and its findings never
// form incidents, so a selftest sends nothing on any notification channel
// (Slack, email, webhooks, Jira, PagerDuty, ServiceNow). An asset with any
// other identifier is not one, so a batch cannot silence a real asset by
// adding the scheme to it; and only an admin may submit the scheme at all
// (AllowSelftest).
const SelftestScheme = "selftest"

// selftestAsset is true for a selftest asset a.
const selftestAsset = `EXISTS (SELECT 1 FROM asset_identifiers si WHERE si.asset_id = a.id AND si.scheme = '` + SelftestScheme + `'
	  AND NOT EXISTS (SELECT 1 FROM asset_identifiers so WHERE so.asset_id = a.id AND so.scheme <> '` + SelftestScheme + `'))`

// ErrSelftestScheme refuses a batch that names a selftest identifier from
// a caller that may not create selftest assets. It is an ErrInvalid.
var ErrSelftestScheme error = reservedScheme{}

type reservedScheme struct{}

func (reservedScheme) Error() string {
	return "the " + SelftestScheme + " identifier scheme is reserved for stackurity selftest, which needs an admin's API token"
}

func (reservedScheme) Is(target error) bool { return target == ErrInvalid }

type selftestKey struct{}

// AllowSelftest marks ctx as an admin's: only then may Ingest store a batch
// with a selftest identifier. Agents, CI scans, SBOM uploads and
// integrations never get it, so none of them can keep an asset off every
// alert channel.
func AllowSelftest(ctx context.Context) context.Context {
	return context.WithValue(ctx, selftestKey{}, true)
}

// checkSelftestScheme refuses a batch whose asset has a selftest
// identifier unless ctx allows it.
func checkSelftestScheme(ctx context.Context, b *model.ObservationBatch) error {
	if ok, _ := ctx.Value(selftestKey{}).(bool); ok {
		return nil
	}
	for _, id := range b.Asset.Identifiers {
		if id.Scheme == SelftestScheme {
			return ErrSelftestScheme
		}
	}
	return nil
}
