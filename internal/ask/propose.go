package ask

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/stackurity/stackurity/internal/mcp"
	"github.com/stackurity/stackurity/internal/store"
)

// Ask Stackurity may propose changes, never make them. When the
// organisation allows it (Question.Propose), the model is offered the
// propose tools (mcp.ProposeTools). Calling one runs the write tool's plan,
// which only reads, and stores the preview with its confirm code as a
// proposal (store.AskProposal) that the panel shows as a card with Apply
// and Dismiss. The model gets the preview's text only, never the code, and
// nothing it can call applies anything: the tools' API (the API's askAPI)
// refuses every request that is not a GET. Only the person's click, a
// separate request from their browser, applies a proposal (the API's
// ask_proposals.go).
//
// Guards against text in tool results steering the model into proposing:
//   - at most one proposal per answer (MaxProposalsPerAnswer); further
//     propose calls get a "not run" result;
//   - the system prompt says to propose only when the person asked for a
//     change in their own words;
//   - when the person's question has no words asking for a change
//     (AskedForChange), the proposal is still shown, but its card says
//     "Ask suggested this; you didn't ask for a change".

// MaxProposalsPerAnswer is how many changes one answer may propose.
const MaxProposalsPerAnswer = 1

const notRunProposal = "Not run: an answer may propose at most one change. Tell the person about the change already proposed; " +
	"they can ask for another one next."

// changeWords are words that ask for a change, as a person would type them
// ("assign these to me", "snooze it until Friday", "yes, do it"). The
// heuristic is deliberately simple and only decides whether a proposal's
// card carries the "you didn't ask for a change" note; it never lets
// anything be applied. A question ("which servers run PHP 7?", "what
// should I fix first?") has none of them.
var changeWords = regexp.MustCompile(`(?i)\b(assign|reassign|give (it|them|these|those) to|hand (it|them) (over|to)|take (it|them|these|those|this)|` +
	`snooze|mute|silence|postpone|defer|ignore|suppress|dismiss|accept (the )?risk|mark (it|them|these|those|this|as)|` +
	`(check|scan)(\s+\S+){0,4}\s+again|re-?check|re-?scan|re-?run|` +
	`rename|call (it|the project)|add|put|move|change|apply|propose|connect|set ?up|install|enrol+|hook (it |them )?up|integrate|` +
	`do (it|that|this|so)|go ahead|please do|yes|yep|confirm)\b`)

// AskedForChange reports whether text, the person's latest message, has
// words that ask for a change.
func AskedForChange(text string) bool { return changeWords.MatchString(text) }

// proposer runs the propose tools of one answer.
type proposer struct {
	e   *Engine
	q   Question
	seq int
	// done: this answer has proposed its one change.
	done bool
}

// run previews the change and stores it as a proposal. The model's result
// says what would change and that nothing has; the confirm code stays in
// the store.
func (p *proposer) run(ctx context.Context, api mcp.API, u ToolUse, emit func(Event)) map[string]any {
	tool, _ := mcp.ProposedTool(u.Name)
	var args map[string]any
	if len(u.Input) > 0 {
		if err := json.Unmarshal(u.Input, &args); err != nil {
			return toolResult(u.ID, "The tool input is not a JSON object.", true)
		}
	}
	if args == nil {
		args = map[string]any{}
	}
	pv, err := mcp.PreviewChange(ctx, api, tool, args)
	if err != nil {
		return toolResult(u.ID, ErrorText(err), true)
	}
	delete(args, "confirm")
	pr, err := p.e.Store.CreateAskProposal(context.WithoutCancel(ctx), p.q.UserID, p.q.Conversation.ID, store.NewAskProposal{
		QuestionSeq: p.seq, Tool: tool, Args: args, Summary: pv.Summary, Details: pv.Details, Notes: pv.Notes, Code: pv.Code,
		Unrequested: !AskedForChange(p.q.Text)})
	if err != nil {
		p.e.log().Error("assistant: storing a proposal", "err", err)
		return toolResult(u.ID, "The change could not be proposed. Tell the person to make it on the linked page instead.", true)
	}
	p.done = true
	emit(Event{Kind: "proposal", Proposal: pr})
	out := map[string]any{"status": "proposed", "changed": "nothing", "will": pv.Summary, "details": pv.Details,
		"next": "The person now sees this change as a card under your answer, with Apply and Dismiss buttons. Nothing changes unless " +
			"they click Apply. Say that in one short sentence. Never say the change is done."}
	if len(pv.Notes) > 0 {
		out["notes"] = pv.Notes
	}
	return toolResult(u.ID, ToolResultText(u.Name, out), false)
}
