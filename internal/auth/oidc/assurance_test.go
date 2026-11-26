package oidc

import (
	"compress/gzip"
	json "encoding/json/v2"
	"os"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
)

type oracleCase struct {
	Claims   string   `json:"claims"`
	Policy   int      `json:"policy"`
	Level    string   `json:"level"`
	Reason   string   `json:"reason"`
	ACR      *string  `json:"acr"`
	AMR      []string `json:"amr"`
	AuthTime *int64   `json:"auth_time"`
}

type oracleFile struct {
	Policies []map[string][]string `json:"policies"`
	Cases    []oracleCase          `json:"cases"`
}

func policyFrom(m map[string][]string) AssurancePolicy {
	return AssurancePolicy{MFAACR: m["OIDC_MFA_ACR_VALUES"], MFAAMR: m["OIDC_MFA_AMR_VALUES"],
		PhishingACR: m["OIDC_PHISHING_RESISTANT_ACR_VALUES"], PhishingAMR: m["OIDC_PHISHING_RESISTANT_AMR_VALUES"]}
}

func evidenceFrom(t *testing.T, text string) evidence {
	t.Helper()
	var c claims
	if err := json.Unmarshal([]byte(text), &c); err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return c.evidence()
}

// TestAssuranceMatchesPython replays the corpus of testdata/
// assurance_oracle.py: level, reason and the normalized acr, amr and
// auth_time of evaluate_oidc_assurance for every case.
func TestAssuranceMatchesPython(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/assurance_oracle.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var corpus oracleFile
	if err := json.UnmarshalRead(zr, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) < 10000 {
		t.Fatalf("corpus has %d cases", len(corpus.Cases))
	}
	for _, c := range corpus.Cases {
		got := policyFrom(corpus.Policies[c.Policy]).assess(evidenceFrom(t, c.Claims))
		wantACR := ""
		if c.ACR != nil {
			wantACR = *c.ACR
		}
		var gotTime *int64
		if !got.AuthTime.IsZero() {
			v := got.AuthTime.Unix()
			gotTime = &v
		}
		if string(got.Level) != c.Level || got.Reason != c.Reason || got.ACR != wantACR ||
			!slices.Equal(got.AMR, c.AMR) && (len(got.AMR) != 0 || len(c.AMR) != 0) ||
			(gotTime == nil) != (c.AuthTime == nil) || gotTime != nil && *gotTime != *c.AuthTime {
			t.Fatalf("claims %s policy %d: Go %+v, Python %s %s acr=%v amr=%v auth_time=%v",
				c.Claims, c.Policy, got, c.Level, c.Reason, c.ACR, c.AMR, c.AuthTime)
		}
	}
}

func TestAssuranceDefaultsToBasic(t *testing.T) {
	t.Parallel()
	for _, text := range []string{`{}`, `{"acr":"urn:mfa","amr":["otp"],"auth_time":1700000000}`} {
		got := AssurancePolicy{}.assess(evidenceFrom(t, text))
		if got.Level != auth.AssuranceBasic || got.Reason != "no_configured_match" {
			t.Fatalf("%s: %+v", text, got)
		}
	}
}

func FuzzAssessEvidence(f *testing.F) {
	f.Add(`{"acr":"mfa","amr":["otp","hwk"],"auth_time":1700000000}`)
	f.Add(`{"amr":[1],"auth_time":1e3}`)
	pol := AssurancePolicy{MFAACR: []string{"mfa"}, MFAAMR: []string{"otp"}, PhishingAMR: []string{"hwk"}}
	f.Fuzz(func(t *testing.T, text string) {
		var c claims
		if json.Unmarshal([]byte(text), &c) != nil {
			return
		}
		a := pol.assess(c.evidence())
		if a.Level != auth.AssuranceBasic && a.AuthTime.IsZero() {
			t.Fatalf("raised assurance without auth_time: %+v", a)
		}
		if len(a.AMR) > maxAMRValues {
			t.Fatalf("%d amr values", len(a.AMR))
		}
	})
}
