package protonauth

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1; this is what authenticator apps and Proton use.
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// generateTOTP computes an RFC 6238 TOTP code (SHA-1, 6 digits, 30s step)
// from a base32-encoded secret, matching Proton Authenticator / Google
// Authenticator defaults. Spaces, case and padding in the secret are tolerated.
func generateTOTP(secret string, now time.Time) (string, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	clean = strings.TrimRight(clean, "=")
	if clean == "" {
		return "", errors.New("TOTP secret is empty")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("TOTP secret is not valid base32: %w", err)
	}

	unix := now.Unix()
	if unix < 0 {
		return "", errors.New("time is before the Unix epoch")
	}
	counter := uint64(unix) / 30 // unix is non-negative, checked above
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", bin%1_000_000), nil
}
