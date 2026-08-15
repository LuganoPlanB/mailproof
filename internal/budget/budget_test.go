package budget

import "testing"

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestValidateRejectsUnsafeLimit(t *testing.T) {
	limits := Default()
	limits.MessageBytes = 0
	if err := limits.Validate(); err == nil {
		t.Fatal("Validate accepted zero")
	}
}

func TestValidateRejectsLeaseRenewalAfterExpiry(t *testing.T) {
	limits := Default()
	limits.LeaseRenewal = limits.WorkerLease
	if err := limits.Validate(); err == nil {
		t.Fatal("Validate accepted late lease renewal")
	}
}
