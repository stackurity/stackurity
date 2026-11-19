package license

// What a refusal for a paid feature tells clients about getting it. The API
// adds an Offer to its 402 plan_required errors and lists one per missing
// feature in GET /plan/options; MCP renders it as one short line, adapted to
// the client (internal/mcp, offer.go). An Offer only describes plans: it is
// never a checkout, and its link is the informational plans page.

// PlansURL is the public page that lists the plans and their prices.
const PlansURL = "https://stackurity.ai/pricing.html"

// Offer says how an organisation could get a paid feature its plan lacks.
type Offer struct {
	Feature Feature `json:"feature"`
	// FeatureName names what was asked for ("Reachability", "PCI DSS 4.0
	// evidence").
	FeatureName string `json:"feature_name"`
	// Hosted: plans are bought on Stackurity Cloud. False: a self-hosted
	// server, where a licence is (IncludedIn then names editions).
	Hosted bool `json:"hosted"`
	// IncludedIn names the plans (Cloud) or licence editions (self-hosted)
	// that include the feature, smallest first.
	IncludedIn []string `json:"included_in"`
	// Plan is the smallest plan that includes the feature, with its price
	// in the organisation's currency where the server knows it. Nil for an
	// add-on, and for a feature no listed plan includes.
	Plan *Price `json:"plan,omitempty"`
	// Addon is set for a feature sold as an add-on (the Compliance
	// add-on): its price on top of the plans in On.
	Addon *Price `json:"addon,omitempty"`
	// TrialAvailable is true only when this organisation can still start a
	// free trial that includes the feature; TrialDays is its length.
	TrialAvailable bool `json:"trial_available"`
	TrialDays      int  `json:"trial_days,omitempty"`
	// PlansURL is the informational plans page, never a checkout.
	PlansURL string `json:"plans_url"`
}

// Price is a plan's or an add-on's price.
type Price struct {
	Name string `json:"name"`
	// Price is in the currency's main unit as a decimal ("99", "1.50");
	// empty when the server does not know it (self-hosted).
	Price    string `json:"price,omitempty"`
	Currency string `json:"currency,omitempty"` // USD, EUR or INR
	Interval string `json:"interval,omitempty"` // month or year
	// On: for an add-on, the plans it can be added to.
	On []string `json:"on,omitempty"`
}

// featureNames are the features' names in refusals and plan options.
var featureNames = map[Feature]string{
	Remediation:          "Automatic fixing",
	Teams:                "Working with several teams",
	EvidenceReport:       "The evidence report and pack (SOC 2, ISO 27001)",
	SSO:                  "Single sign-on",
	EnterprisePacks:      "Enterprise stack packs",
	PhishingResistantMFA: "Phishing-resistant sign-in for admins",
	FixLoop:              "Verified closure",
	ComplianceAddon:      "The Compliance add-on",
	Reachability:         "Reachability",
}

// featureDescriptions say what each feature does, for plan options.
var featureDescriptions = map[Feature]string{
	Remediation:          "Policy-controlled package upgrades on hosts, and Renovate pull requests for repositories.",
	Teams:                "More than one team, routing findings by team, fix deadlines and escalation.",
	EvidenceReport:       "The patch-management evidence report, and the evidence pack for SOC 2 and ISO 27001:2022 audits.",
	SSO:                  "Sign-in through the organisation's own OpenID Connect or SAML 2.0 identity provider.",
	EnterprisePacks:      "Stack packs for enterprise technologies such as SAP and Oracle.",
	PhishingResistantMFA: "Lets the organisation require admins to sign in with a passkey or security key.",
	FixLoop:              "A re-check right after a merged pull request or a remediation run, the pull request that fixed each finding, time to fix against the SLA, and the proof export.",
	ComplianceAddon:      "PCI DSS 4.0 and EU Cyber Resilience Act evidence, SBOM and VEX files in the evidence pack, and sending evidence to Vanta and Drata.",
	Reachability:         "Findings in packages that no code imports or no process runs drop one priority level, with reachability filters and views. Reachability evidence is collected in every edition.",
}

// PaidFeatures lists every paid feature, in the order plan options show
// them.
func PaidFeatures() []Feature {
	return []Feature{Reachability, FixLoop, Remediation, Teams, EvidenceReport, ComplianceAddon, SSO, PhishingResistantMFA, EnterprisePacks}
}

// Name is the feature's name for people.
func (f Feature) Name() string {
	if n, ok := featureNames[f]; ok {
		return n
	}
	return string(f)
}

// Description says what the feature does.
func (f Feature) Description() string { return featureDescriptions[f] }

// editionNames are the editions' names for people.
var editionNames = map[Edition]string{Community: "Community", Pro: "Pro", Enterprise: "Enterprise"}

// LowestEdition is the smallest edition that includes f by itself
// (Enterprise for the add-on).
func LowestEdition(f Feature) Edition {
	for _, e := range []Edition{Pro, Enterprise} {
		if e.Includes(f) {
			return e
		}
	}
	return Enterprise
}

// SelfHostedOffer is the offer on a self-hosted server: the licence
// editions that include f (and, for an add-on, the licence it is added
// to). No prices or trial: the server does not know them.
func SelfHostedOffer(f Feature) *Offer {
	o := &Offer{Feature: f, FeatureName: f.Name(), IncludedIn: []string{}, PlansURL: PlansURL}
	for _, e := range []Edition{Pro, Enterprise} {
		if e.Includes(f) {
			o.IncludedIn = append(o.IncludedIn, editionNames[e])
		}
	}
	if IsAddon(f) {
		o.Addon = &Price{Name: f.addonName(), On: []string{editionNames[Pro]}}
	}
	return o
}

// addonName is an add-on's name without the article.
func (f Feature) addonName() string {
	if f == ComplianceAddon {
		return "Compliance add-on"
	}
	return f.Name()
}

// AddonName is the name of the add-on f is sold as ("Compliance add-on").
func (f Feature) AddonName() string { return f.addonName() }
