package otp

import (
	"testing"
	"time"
)

// RFC 4226 appendix D: secret "12345678901234567890", counters 0 to 9.
func TestHOTPVectors(t *testing.T) {
	t.Parallel()
	key := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		got, err := HOTP(key, uint64(counter), 6)
		if err != nil || got != code {
			t.Fatalf("counter %d: HOTP = %q, %v, want %q", counter, got, err, code)
		}
	}
}

// RFC 6238 appendix B, SHA-1 rows (8 digits).
func TestTOTPVectors(t *testing.T) {
	t.Parallel()
	key := []byte("12345678901234567890")
	tests := []struct {
		name string
		unix int64
		code string
	}{
		{"59", 59, "94287082"},
		{"1111111109", 1111111109, "07081804"},
		{"1111111111", 1111111111, "14050471"},
		{"1234567890", 1234567890, "89005924"},
		{"2000000000", 2000000000, "69279037"},
		{"20000000000", 20000000000, "65353130"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := HOTP(key, Step(time.Unix(tt.unix, 0), DefaultPeriod), 8)
			if err != nil || got != tt.code {
				t.Fatalf("got %q, %v, want %q", got, err, tt.code)
			}
		})
	}
}

func TestDecodeSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, text string
		ok         bool
	}{
		{"canonical", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", true},
		{"lower case", "gezdgnbvgy3tqojqgezdgnbvgy3tqojq", true},
		{"padded", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====", true},
		{"too short", "GEZDGNBVGY3TQOJQ", false},
		{"not base32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ1", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeSecret(tt.text)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestHOTPDigits(t *testing.T) {
	t.Parallel()
	for _, digits := range []int{5, 10} {
		if _, err := HOTP([]byte("k"), 0, digits); err == nil {
			t.Fatalf("%d digits accepted", digits)
		}
	}
}

func FuzzDecodeSecret(f *testing.F) {
	f.Add("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	f.Add("====")
	f.Fuzz(func(t *testing.T, text string) {
		key, err := DecodeSecret(text)
		if err == nil && len(key)*8 < MinSecretBits {
			t.Fatalf("short key accepted: %x", key)
		}
	})
}
