package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/license"
)

// Plan offers. When a tool asks for a paid feature the organisation's plan
// does not include, the API answers 402 plan_required with a license.Offer;
// the tool's error is then one short line naming the feature and the plan
// or add-on that includes it (offerLine), not the raw API error. Offers
// appear only there and in plan_options, a tool the person calls to ask
// about plans: never appended to an answer that worked (the Anthropic
// directory policy and OpenAI's app guidelines forbid promotional content
// in tool results).
//
// ChatGPT (OpenAI's MCP client) gets no price, trial or other purchase
// prompt, only the plan's name and the informational plans page; every
// other client gets the price in the organisation's currency from the
// server's plan configuration, and the trial when one is open. No client
// gets a checkout link.

// ClientInfo identifies the MCP client, from what it says about itself.
type ClientInfo struct {
	// Name is clientInfo.name from initialize (or a 2026-07-28 request's
	// _meta).
	Name string
	// UserAgent is the HTTP User-Agent of a request to /mcp.
	UserAgent string
	// OAuthClient and RedirectHost are the assistant's OAuth client_name
	// and redirect host, for a connection made with OAuth.
	OAuthClient  string
	RedirectHost string
}

// openAIMarks are what OpenAI's clients carry: ChatGPT's connector
// identifies itself as "openai-mcp" (clientInfo.name and User-Agent
// "openai-mcp/1.0.0"), registers OAuth clients named for ChatGPT and
// redirects to chatgpt.com. Any one of them is enough: a client wrongly
// treated as ChatGPT only loses the price, never the plan's name.
var openAIMarks = []string{"openai", "chatgpt"}

// OpenAI reports whether the client is ChatGPT or another OpenAI client.
func (c ClientInfo) OpenAI() bool {
	for _, v := range []string{c.Name, c.UserAgent, c.OAuthClient, c.RedirectHost} {
		v = strings.ToLower(v)
		for _, m := range openAIMarks {
			if strings.Contains(v, m) {
				return true
			}
		}
	}
	return false
}

type clientKey struct{}

func withClient(ctx context.Context, c ClientInfo) context.Context {
	return context.WithValue(ctx, clientKey{}, c)
}

func clientFrom(ctx context.Context) ClientInfo {
	c, _ := ctx.Value(clientKey{}).(ClientInfo)
	return c
}

// requestClientName is the clientInfo.name a 2026-07-28 request may carry
// in its _meta.
func requestClientName(params json.RawMessage) string {
	var p struct {
		Meta struct {
			Client struct {
				Name string `json:"name"`
			} `json:"io.modelcontextprotocol/clientInfo"`
		} `json:"_meta"`
		ClientInfo struct {
			Name string `json:"name"`
		} `json:"clientInfo"`
	}
	_ = json.Unmarshal(params, &p)
	if p.Meta.Client.Name != "" {
		return p.Meta.Client.Name
	}
	return p.ClientInfo.Name
}

// ToolErrorText is errorText for other callers of the read tools (Ask
// Stackurity): plan_required as its offer line.
func ToolErrorText(ctx context.Context, err error) string { return errorText(ctx, err) }

// errorText is a tool error's text: plan_required as its offer line, any
// other error as it is.
func errorText(ctx context.Context, err error) string {
	var ae *client.APIError
	if errors.As(err, &ae) && ae.Status == 402 && ae.Code == "plan_required" && ae.Offer != nil && ae.Offer.FeatureName != "" {
		return offerLine(ae.Offer, clientFrom(ctx).OpenAI())
	}
	return err.Error()
}

var currencySigns = map[string]string{"USD": "$", "EUR": "€", "INR": "₹"}

// money is "$35 a month", or "" without a price.
func money(p *license.Price) string {
	if p == nil || p.Price == "" {
		return ""
	}
	amount := p.Currency + " " + p.Price
	if sign, ok := currencySigns[p.Currency]; ok {
		amount = sign + p.Price
	}
	if p.Interval != "" {
		amount += " a " + p.Interval
	}
	return amount
}

// orList is "Team", "Team or Business", "Team, Business or Enterprise".
func orList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

func plansURL(o *license.Offer) string {
	if strings.HasPrefix(o.PlansURL, "https://") {
		return o.PlansURL
	}
	return license.PlansURL
}

func includes(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// partOf names what includes the feature, without prices: "the Compliance
// add-on", "the Team plan", "a Pro or Enterprise licence".
func partOf(o *license.Offer) string {
	switch {
	case o.Addon != nil:
		return "the " + o.Addon.Name
	case !o.Hosted:
		return "a " + orList(o.IncludedIn) + " licence"
	case o.Plan != nil:
		return "the " + o.Plan.Name + " plan"
	case len(o.IncludedIn) > 0:
		return "the " + orList(o.IncludedIn) + " plan"
	}
	return "a paid plan"
}

// offerLine is one short line for a plan_required refusal. restricted
// (ChatGPT) leaves out prices and trials.
func offerLine(o *license.Offer, restricted bool) string {
	name := o.FeatureName
	link := " Plans: " + plansURL(o)
	if restricted {
		return name + " is not included in your current plan; it is part of " + partOf(o) + "." + link
	}
	line := name + " is not included in this organisation's plan. "
	switch {
	case o.Addon != nil && o.Hosted:
		line += "It is part of the " + o.Addon.Name
		if m := money(o.Addon); m != "" {
			line += ": +" + m
			if len(o.Addon.On) > 0 {
				line += " on the " + orList(o.Addon.On) + " plan"
			}
		}
		if includes(o.IncludedIn, "Enterprise") {
			line += ", included in Enterprise"
		}
		line += "."
	case o.Addon != nil:
		line += "It needs the " + o.Addon.Name + " on a " + orList(o.Addon.On) + " licence"
		if includes(o.IncludedIn, "Enterprise") {
			line += ", or an Enterprise licence"
		}
		line += "."
	case !o.Hosted:
		line += "It needs a " + orList(o.IncludedIn) + " licence."
	case o.Plan != nil:
		line += "It is included in the " + o.Plan.Name + " plan"
		if m := money(o.Plan); m != "" {
			line += " (" + m + ")"
		}
		if len(o.IncludedIn) > 1 && o.IncludedIn[len(o.IncludedIn)-1] != o.Plan.Name {
			line += " and higher plans"
		}
		line += "."
		// A trial only ever for an edition feature, never an add-on.
		if o.TrialAvailable && o.TrialDays > 0 {
			line += " A " + strconv.Itoa(o.TrialDays) + "-day free trial is available."
		}
	default:
		line += "It is part of " + partOf(o) + "."
	}
	return line + link
}
