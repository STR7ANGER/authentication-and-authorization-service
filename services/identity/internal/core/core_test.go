package core

import "testing"

func TestPasswordPolicy(t *testing.T) {
	if ValidatePassword("StrongPassword9") != nil { t.Fatal("strong password rejected") }
	if ValidatePassword("weakpassword") == nil { t.Fatal("weak password accepted") }
}
func TestRiskEvaluation(t *testing.T) {
	risk := EvaluateRisk(LoginContext{DeviceKnown: false, PreviousCountry: "IN", Country: "US", FailedAttempts: 5})
	if risk.Score != 115 || !risk.StepUp || len(risk.Reasons) != 3 { t.Fatalf("unexpected risk: %#v", risk) }
}
func TestRefreshReuseRevokesFamily(t *testing.T) {
	family := NewFamily()
	if family.Rotate("one") != nil { t.Fatal("first rotation failed") }
	if family.Rotate("one") != ErrRefreshReuse || !family.Revoked() { t.Fatal("reuse did not revoke family") }
}
