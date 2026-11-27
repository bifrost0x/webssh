package hostops

import (
	json "encoding/json/v2"
	"os"
	"testing"
)

// banner_oracle.json is recorded from describe_banner by
// internal/hosts/testdata/platform_oracle.py.
func TestDescribeBannerMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/banner_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Raw    []int `json:"raw"`
		Result *struct {
			Software string  `json:"software"`
			Comment  string  `json:"comment"`
			Platform *string `json:"platform"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 300 {
		t.Fatalf("only %d cases", len(cases))
	}
	for i, c := range cases {
		line := make([]byte, len(c.Raw))
		for j, v := range c.Raw {
			line[j] = byte(v)
		}
		got, ok := DescribeBanner(line)
		if (c.Result != nil) != ok {
			t.Errorf("case %d %q: ok %v, Python %v", i, line, ok, c.Result != nil)
			continue
		}
		if !ok {
			continue
		}
		want := Banner{Software: c.Result.Software, Comment: c.Result.Comment}
		if c.Result.Platform != nil {
			want.Platform = *c.Result.Platform
		}
		if got != want {
			t.Errorf("case %d %q: %+v, Python %+v", i, line, got, want)
		}
	}
}

func FuzzDescribeBanner(f *testing.F) {
	f.Add([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"))
	f.Add([]byte("SSH-2.0-OpenSSH_for_Windows_9.5"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, ok := DescribeBanner(raw)
		if !ok {
			return
		}
		if len(b.Software) > 80 || len(b.Comment) > 80 {
			t.Fatalf("too long: %+v", b)
		}
		for _, s := range []string{b.Software, b.Comment} {
			for i := range len(s) {
				if s[i] < 0x20 || s[i] > 0x7e {
					t.Fatalf("not printable ASCII: %q", s)
				}
			}
		}
	})
}
