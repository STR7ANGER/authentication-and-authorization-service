package core

import (
	"errors"
	"strings"
	"sync"
	"unicode"
)

var ErrWeakPassword = errors.New("password does not meet policy")
var ErrRefreshReuse = errors.New("refresh token reuse detected")

func ValidatePassword(value string) error {
	if len(value) < 12 || len(value) > 128 { return ErrWeakPassword }
	var upper, lower, digit bool
	for _, char := range value { upper = upper || unicode.IsUpper(char); lower = lower || unicode.IsLower(char); digit = digit || unicode.IsDigit(char) }
	if !upper || !lower || !digit { return ErrWeakPassword }
	return nil
}

type LoginContext struct { DeviceKnown bool `json:"deviceKnown"`; PreviousCountry string `json:"previousCountry"`; Country string `json:"country"`; FailedAttempts int `json:"failedAttempts"` }
type Risk struct { Score int `json:"score"`; Reasons []string `json:"reasons"`; StepUp bool `json:"stepUp"` }
func EvaluateRisk(input LoginContext) Risk {
	score := 0; reasons := []string{}
	if !input.DeviceKnown { score += 25; reasons = append(reasons, "NEW_DEVICE") }
	if input.PreviousCountry != "" && !strings.EqualFold(input.PreviousCountry, input.Country) { score += 50; reasons = append(reasons, "COUNTRY_CHANGE") }
	if input.FailedAttempts >= 5 { score += 40; reasons = append(reasons, "FAILED_ATTEMPT_VELOCITY") }
	return Risk{Score: score, Reasons: reasons, StepUp: score >= 50}
}

type Family struct { mu sync.Mutex; used map[string]bool; revoked bool }
func NewFamily() *Family { return &Family{used: map[string]bool{}} }
func (family *Family) Rotate(tokenID string) error {
	family.mu.Lock(); defer family.mu.Unlock()
	if family.revoked || family.used[tokenID] { family.revoked = true; return ErrRefreshReuse }
	family.used[tokenID] = true
	return nil
}
func (family *Family) Revoked() bool { family.mu.Lock(); defer family.mu.Unlock(); return family.revoked }
