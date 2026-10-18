package protonauth

import (
	"testing"
	"time"
)

func TestGenerateTOTP(t *testing.T) {
	// RFC 6238 test secret, truncated to the six digits used by Proton and
	// common authenticator applications.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	tests := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1234567890, "005924"},
	}

	for _, test := range tests {
		got, err := generateTOTP(secret, time.Unix(test.unix, 0))
		if err != nil {
			t.Fatalf("generateTOTP(%d): %v", test.unix, err)
		}
		if got != test.want {
			t.Errorf("generateTOTP(%d) = %q, want %q", test.unix, got, test.want)
		}
	}
}

func TestGenerateTOTPAcceptsSpacesCaseAndPadding(t *testing.T) {
	now := time.Unix(59, 0)
	want, err := generateTOTP("MZXW6", now)
	if err != nil || want == "" {
		t.Fatalf("baseline: %q, %v", want, err)
	}
	got, err := generateTOTP("mz xw6===", now)
	if err != nil || got != want {
		t.Fatalf("generateTOTP() = %q, %v; want %q", got, err, want)
	}
}

func TestGenerateTOTPRejectsInvalidSecret(t *testing.T) {
	for _, secret := range []string{"not valid!", "", "   ", "==="} {
		if got, err := generateTOTP(secret, time.Unix(59, 0)); err == nil {
			t.Errorf("generateTOTP(%q) = %q, want an error", secret, got)
		}
	}
}
