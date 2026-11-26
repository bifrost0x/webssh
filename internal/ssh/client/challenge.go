package client

import (
	"context"
	"errors"
)

// Bounds of one keyboard-interactive round as the user sees it. A server
// that asks more is refused.
const (
	maxQuestions     = 8
	maxQuestionChars = 512
	maxAnswerBytes   = 1024
)

var errChallengeDeclined = errors.New("keyboard-interactive round declined")

// askUser puts one round to the user. The time the user takes is not
// part of the handshake budget; the hop context bounds it.
func askUser(ctx context.Context, wd *watchdog, ch Challenger, h hop, name, instruction string, questions []string, echos []bool) ([]string, error) {
	if len(questions) > maxQuestions {
		return nil, errAuthExhausted
	}
	q := Challenge{Role: h.role, Host: h.Host, Port: h.Port,
		Name: cleanText(name, maxQuestionChars), Instruction: cleanText(instruction, maxBannerChars)}
	for i, text := range questions {
		q.Questions = append(q.Questions, Question{Text: cleanText(text, maxQuestionChars), Echo: echos[i]})
	}
	resume := wd.pause()
	answers, err := ch.Challenge(ctx, q)
	resume()
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, errors.Join(errChallengeDeclined, err)
	case len(answers) != len(questions):
		return nil, errAuthExhausted
	}
	for _, a := range answers {
		if len(a) > maxAnswerBytes {
			return nil, errAuthExhausted
		}
	}
	return answers, nil
}

// cleanText applies the banner rules to a remote-supplied text and bounds
// it to limit characters.
func cleanText(raw string, limit int) string {
	text := []rune(sanitizeBanner(raw))
	if len(text) > limit {
		text = text[:limit]
	}
	return string(text)
}
