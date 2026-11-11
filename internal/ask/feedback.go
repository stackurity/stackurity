package ask

import (
	"strings"
	"unicode"
)

// Implicit feedback signals the server can tell from a question and its
// answer, without asking the person. Each is stored as metadata only (no
// text): see store.AskSignal.

// rephraseThreshold is the word overlap (Jaccard) above which a question is
// taken to be an earlier one asked again.
const rephraseThreshold = 0.6

// rephraseMinWords: questions shorter than this ("yes", "and db-1?") are
// follow-ups, never counted as rephrasings.
const rephraseMinWords = 3

// stopwords are left out when comparing questions.
var stopwords = map[string]bool{
	"a": true, "an": true, "the": true, "is": true, "are": true, "was": true, "were": true, "do": true, "does": true, "did": true,
	"i": true, "we": true, "my": true, "our": true, "me": true, "you": true, "it": true, "this": true, "that": true, "these": true,
	"of": true, "on": true, "in": true, "to": true, "for": true, "with": true, "and": true, "or": true, "at": true, "by": true,
	"please": true, "can": true, "could": true, "would": true, "what": true, "which": true, "how": true, "any": true, "all": true,
}

// questionWords returns the distinct significant words of q, lower case.
func questionWords(q string) map[string]bool {
	words := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '.' && r != '_'
	}) {
		w = strings.Trim(w, ".-_")
		if w != "" && !stopwords[w] {
			words[w] = true
		}
	}
	return words
}

// Rephrased reports whether q asks one of earlier again: the same question
// in other words within the last two questions. earlier holds the person's
// previous questions, oldest first; only the last two count.
func Rephrased(q string, earlier []string) bool {
	if len(earlier) > 2 {
		earlier = earlier[len(earlier)-2:]
	}
	a := questionWords(q)
	if len(a) < rephraseMinWords {
		return false
	}
	for _, e := range earlier {
		b := questionWords(e)
		if len(b) < rephraseMinWords {
			continue
		}
		inter := 0
		for w := range a {
			if b[w] {
				inter++
			}
		}
		union := len(a) + len(b) - inter
		if union > 0 && float64(inter)/float64(union) >= rephraseThreshold {
			return true
		}
	}
	return false
}

// notFoundPhrases are ways an answer says it could not understand the
// question or find what was asked for.
var notFoundPhrases = []string{
	"i couldn't find", "i could not find", "i can't find", "i cannot find", "i was unable to find", "i wasn't able to find",
	"i was not able to find", "i'm unable to find", "no matching", "couldn't find any", "could not find any",
	"i don't understand", "i do not understand", "i'm not sure what you mean", "i am not sure what you mean",
	"couldn't understand", "could not understand", "can you clarify what you mean", "i don't have access to",
}

// SaysNotFound reports whether an answer says it could not understand the
// question or find what it was asked for. Only the first 600 characters
// count: a long answer that mentions one thing it could not find is still
// an answer.
//
// The "## Data gaps" section the prompt asks for is where an answer says
// what it could not find on purpose, so it does not count either: only a
// lead that cannot answer is a reason to try again on a stronger model.
func SaysNotFound(answer string) bool {
	a := strings.ToLower(strings.ReplaceAll(answer, "’", "'"))
	for _, h := range []string{"## data gaps", "**data gaps"} {
		if i := strings.Index(a, h); i >= 0 {
			a = a[:i]
		}
	}
	if len(a) > 600 {
		a = a[:600]
	}
	for _, p := range notFoundPhrases {
		if strings.Contains(a, p) {
			return true
		}
	}
	return false
}

// SnapshotText cleans a message's visible text for a feedback snapshot the
// person agreed to share: invisible characters, credentials and email
// addresses are removed, as in what the tools send the model.
func SnapshotText(s string) string {
	return emailRE.ReplaceAllString(redactSecrets(CleanText(s)), colleague)
}
