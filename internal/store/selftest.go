package store

// SelftestScheme marks the throwaway asset that `stackurity selftest`
// creates (internal/selftest). An asset whose only identifiers have this
// scheme is a selftest asset: it is never announced and its findings never
// form incidents, so a selftest sends nothing on any notification channel
// (Slack, email, webhooks, Jira, PagerDuty, ServiceNow). An asset with any
// other identifier is not one, so a batch cannot silence a real asset by
// adding the scheme to it.
const SelftestScheme = "selftest"

// selftestAsset is true for a selftest asset a.
const selftestAsset = `EXISTS (SELECT 1 FROM asset_identifiers si WHERE si.asset_id = a.id AND si.scheme = '` + SelftestScheme + `'
	  AND NOT EXISTS (SELECT 1 FROM asset_identifiers so WHERE so.asset_id = a.id AND so.scheme <> '` + SelftestScheme + `'))`
