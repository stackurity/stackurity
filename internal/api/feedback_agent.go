package api

// The feedback agent's loop on the queue (docs/feedback-queue.md#the-feedback-agent):
//
//   - A thread under each item that the sender can read: the agent (triage
//     token) and the team (instance administrators) comment with POST
//     /admin/feedback/{id}/comments; {"ask":true} makes the comment a
//     question and moves the item to needs_info. The sender reads the
//     thread in My feedback and answers through the status route
//     (feedbackQueueStatus, an item with "reply"), which puts a needs_info
//     item back to new for the agent.
//   - Approval: an item the agent may not build alone is needs_owner, with
//     owner_reason. An instance administrator, signed in (not an API token,
//     not the triage token), approves it (triaged with approved_at: the
//     agent builds it on its next run) or declines it with a resolution
//     (won't fix, which emails the sender with the approved template).
//   - Emails: received and needs_info to the sender, only with
//     STACKURITY_FEEDBACK_AGENT_EMAILS=on (their wording waits for the
//     owner's approval); "approval needed" to STACKURITY_FEEDBACK_APPROVERS.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/feedback"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

const (
	// feedbackCommentMax is the longest comment, from anyone.
	feedbackCommentMax = 5000
	// feedbackReplyMax is the longest reply a sender can send from My
	// feedback (the website relay takes 16 KB per status request).
	feedbackReplyMax = 2000
	// feedbackPublicBodyMax shortens each comment in the status answer.
	feedbackPublicBodyMax = 1500
	// feedbackStatusBudget keeps the status answer under the relay's
	// 64 KB: threads that do not fit are left out (the installation keeps
	// the one it had) or cut to their newest comments.
	feedbackStatusBudget = 56 << 10
)

var (
	// limitFeedbackReplyIP caps sender replies per address.
	limitFeedbackReplyIP = rateLimit{30, time.Hour}
	// limitFeedbackReceivedEmail caps received emails to one address.
	limitFeedbackReceivedEmail = rateLimit{5, 24 * time.Hour}
)

// requireInstanceAdminSession allows an instance administrator signed in
// with a session: never an API token, a triage token or an assistant, so
// an approval is always a person's click.
func requireInstanceAdminSession(next http.Handler) http.Handler {
	admin := requireInstanceAdmin(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if p == nil || p.User == nil || p.Token != nil || p.FeedbackAgent != nil || p.Assistant != nil {
			writeError(w, 403, "forbidden", "approving feedback needs an instance administrator signed in to the dashboard")
			return
		}
		admin.ServeHTTP(w, r)
	})
}

func validComment(body string, max int) (string, error) {
	body = strings.TrimSpace(body)
	if body == "" || !utf8.ValidString(body) || utf8.RuneCountInString(body) > max {
		return "", badRequest("write a comment of 1 to " + itoa(int64(max)) + " characters")
	}
	return body, nil
}

// addFeedbackComment: {"body": "...", "ask": false}. The agent's token
// writes as the agent, an instance administrator as the team. With ask,
// the sender is asked (needs_info) and emailed the questions.
func (s *Server) addFeedbackComment(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	id, err := feedbackIDParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Body string `json:"body"`
		Ask  bool   `json:"ask"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	body, err := validComment(req.Body, feedbackCommentMax)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	kind := store.FeedbackByTeam
	if p := principal(r); p != nil && p.FeedbackAgent != nil {
		kind = store.FeedbackByAgent
	}
	before, after, err := s.Store.AddFeedbackComment(r.Context(), id, kind, feedbackActor(r), body, req.Ask)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Ask && before.Status != store.FeedbackNeedsInfo {
		s.emailFeedbackQuestions(r.Context(), after, body)
	}
	comments, err := s.Store.ListFeedbackComments(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]any{"item": after, "comments": comments})
}

// approveFeedback: {"note": "..."} (optional). The item goes to triaged
// with approved_at; the agent builds it on its next run.
func (s *Server) approveFeedback(w http.ResponseWriter, r *http.Request) {
	s.decideFeedback(w, r, true)
}

// declineFeedback: {"resolution": "..."} (required; the sender reads it).
func (s *Server) declineFeedback(w http.ResponseWriter, r *http.Request) {
	s.decideFeedback(w, r, false)
}

func (s *Server) decideFeedback(w http.ResponseWriter, r *http.Request, approve bool) {
	if !s.queueOn(w) {
		return
	}
	id, err := feedbackIDParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Note       string `json:"note"`
		Resolution string `json:"resolution"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	text := strings.TrimSpace(req.Note)
	if !approve {
		text = strings.TrimSpace(req.Resolution)
		if text == "" {
			s.fail(w, r, badRequest("declining needs a resolution: the reason the sender will read"))
			return
		}
	}
	if utf8.RuneCountInString(text) > 2000 || !utf8.ValidString(text) {
		s.fail(w, r, badRequest("keep it under 2000 characters"))
		return
	}
	_, after, err := s.Store.DecideFeedbackItem(r.Context(), id, approve, text, feedbackActor(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	action := "feedback.approve"
	if !approve {
		action = "feedback.decline"
		s.emailFeedbackSender(r.Context(), after)
	}
	s.Log.Info("feedback decided", "ref", after.Ref, "action", action, "by", feedbackActor(r))
	writeJSON(w, 200, after)
}

// agentEmailOK says whether the feedback agent's sender emails can go.
func (s *Server) agentEmailOK(it *store.FeedbackItem, tmpl string) bool {
	if it.ContactEmail == "" {
		return false
	}
	if !s.FeedbackQueue.AgentEmails || s.AccountMail == nil {
		s.Log.Info("feedback sender not emailed: STACKURITY_FEEDBACK_AGENT_EMAILS is off or no mail is configured", "ref", it.Ref, "template", tmpl)
		return false
	}
	return true
}

// sendFeedbackAgentEmail renders and sends one of the agent's emails and
// records it in the item's history (not notified_at, which is the
// released or won't-fix email's once-only mark).
func (s *Server) sendFeedbackAgentEmail(ctx context.Context, it *store.FeedbackItem, tmpl string, d feedback.EmailData, link, linkLabel string) {
	m, err := feedback.RenderEmail(tmpl, d)
	if err != nil {
		s.Log.Error("feedback email", "err", err)
		return
	}
	msg := notify.FeedbackUpdateEmail(m.Subject, m.Body, time.Now().UTC())
	if link != "" {
		msg.Link, msg.LinkLabel = link, linkLabel
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.AccountMail.SendMail(ctx, []string{it.ContactEmail}, msg); err != nil {
		s.Log.Error("feedback email not sent", "ref", it.Ref, "template", tmpl, "err", err)
		return
	}
	if err := s.Store.RecordFeedbackEmail(ctx, it.ID, tmpl); err != nil {
		s.Log.Error("feedback email sent but not recorded", "ref", it.Ref, "err", err)
	}
}

// emailFeedbackReceived confirms a new item to its sender, quoting what they
// sent (shortened, links defanged). At most five a day to one address.
func (s *Server) emailFeedbackReceived(ctx context.Context, it *store.FeedbackItem) {
	if !s.agentEmailOK(it, "received") {
		return
	}
	ok, err := s.limiter.check(ctx, limitHit{"feedback-received-email", strings.ToLower(it.ContactEmail), limitFeedbackReceivedEmail})
	if err != nil || !ok {
		s.Log.Info("feedback received email skipped: too many to this address today", "ref", it.Ref)
		return
	}
	s.sendFeedbackAgentEmail(ctx, it, "received", feedback.EmailData{Ref: it.Ref, Summary: it.Description, Source: it.Source,
		Attachments: it.Attachments}, "", "")
}

// emailFeedbackQuestions asks the sender for details, with a link to My
// feedback when they sent it from Stackurity Cloud (this server).
func (s *Server) emailFeedbackQuestions(ctx context.Context, it *store.FeedbackItem, questions string) {
	if !s.agentEmailOK(it, "needs_info") {
		return
	}
	link := ""
	if it.Source == "cloud" && s.BaseURL != "" {
		link = strings.TrimRight(s.BaseURL, "/") + "/feedback"
	}
	s.sendFeedbackAgentEmail(ctx, it, "needs_info", feedback.EmailData{Ref: it.Ref, Source: it.Source, Questions: questions, Link: link},
		link, "Answer in My feedback")
}

// emailFeedbackApprovers tells STACKURITY_FEEDBACK_APPROVERS that an item
// waits for their decision.
func (s *Server) emailFeedbackApprovers(ctx context.Context, it *store.FeedbackItem) {
	if len(s.FeedbackQueue.Approvers) == 0 || s.AccountMail == nil {
		return
	}
	link := strings.TrimRight(s.BaseURL, "/") + "/admin/feedback?item=" + it.Ref
	msg := notify.FeedbackApprovalEmail(it.Ref, feedback.Defang(it.OwnerReason, 600), link, time.Now().UTC())
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.AccountMail.SendMail(ctx, s.FeedbackQueue.Approvers, msg); err != nil {
		s.Log.Error("feedback approval email not sent", "ref", it.Ref, "err", err)
	}
}

// feedbackStatusItem is one item of a status request: the reference, its
// token, and optionally the sender's reply.
type feedbackStatusItem struct {
	Ref   string `json:"ref"`
	Token string `json:"token"`
	Reply string `json:"reply,omitempty"`
}

// feedbackSenderReply stores the reply of one status item; the answer
// says why when it was not stored.
func (s *Server) feedbackSenderReply(ctx context.Context, id int64, it feedbackStatusItem) (stored bool, problem string, err error) {
	body, verr := validComment(it.Reply, feedbackReplyMax)
	if verr != nil {
		return false, "write a reply of 1 to 2000 characters", nil
	}
	_, err = s.Store.FeedbackSenderReply(ctx, id, auth.HashToken(it.Token), body)
	switch {
	case errors.Is(err, store.ErrConflict):
		msg := err.Error()
		if i := strings.Index(msg, ": "); i >= 0 {
			msg = msg[i+2:]
		}
		return false, msg, nil
	case err != nil:
		return false, "", err
	}
	return true, "", nil
}

// fitThreads cuts the comments of each answer to the status budget: each
// body to feedbackPublicBodyMax characters, and each thread to its newest
// comments that still fit. A thread with no room left is nil, so the
// installation keeps the one it had.
func fitThreads(items []any) {
	used := 0
	for _, x := range items {
		st, ok := x.(*store.FeedbackPublic)
		if !ok {
			continue
		}
		base, _ := json.Marshal(store.FeedbackPublic{Ref: st.Ref, Status: st.Status, Resolution: st.Resolution, FixedIn: st.FixedIn,
			UpdatedAt: st.UpdatedAt, ReplyError: st.ReplyError, Replied: st.Replied})
		used += len(base) + 1
		for i := range st.Comments {
			if r := []rune(st.Comments[i].Body); len(r) > feedbackPublicBodyMax {
				st.Comments[i].Body = string(r[:feedbackPublicBodyMax-1]) + "…"
			}
		}
		keep := 0
		size := len(`,"comments":[]`)
		for i := len(st.Comments) - 1; i >= 0; i-- {
			b, _ := json.Marshal(st.Comments[i])
			if used+size+len(b)+1 > feedbackStatusBudget {
				break
			}
			size += len(b) + 1
			keep++
		}
		if keep == 0 && len(st.Comments) > 0 {
			st.Comments = nil
			continue
		}
		st.Comments = st.Comments[len(st.Comments)-keep:]
		used += size
	}
}
