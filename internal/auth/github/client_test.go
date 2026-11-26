package github

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Condition K7: the login and the name are limited in characters, as
// Python's len() counts them, not in bytes.
func TestParseProfileCountsCharacters(t *testing.T) {
	t.Parallel()
	ok := func(body string) Profile {
		t.Helper()
		p, err := parseProfile(http.StatusOK, []byte(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		return p
	}
	login128 := strings.Repeat("ä", 128)
	if p := ok(`{"id": 7, "login": "` + login128 + `"}`); p.Login != login128 || p.UserID != "7" {
		t.Fatalf("128 two-byte characters: %+v", p)
	}
	if _, err := parseProfile(200, []byte(`{"id": 7, "login": "`+strings.Repeat("ä", 129)+`"}`)); !errors.Is(err, errProvider) {
		t.Fatalf("129 characters: %v", err)
	}
	name256 := strings.Repeat("名", 256)
	if p := ok(`{"id": 7, "login": "a", "name": "` + name256 + `"}`); p.DisplayName != name256 {
		t.Fatal("256 three-byte characters dropped")
	}
	if p := ok(`{"id": 7, "login": "a", "name": "` + strings.Repeat("名", 257) + `"}`); p.DisplayName != "" {
		t.Fatal("257 characters kept")
	}
}

func TestParseProfileRefusals(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"id": 1001.0, "login": "a"}`, `{"id": "1001", "login": "a"}`, `{"id": true, "login": "a"}`,
		`{"id": 0, "login": "a"}`, `{"id": -5, "login": "a"}`, `{"id": 1e3, "login": "a"}`,
		`{"id": 1, "login": ""}`, `{"id": 1}`, `{"id": 1, "login": 5}`, `[1]`, `not json`, ``,
	} {
		if _, err := parseProfile(200, []byte(body)); !errors.Is(err, errProvider) {
			t.Errorf("%s: %v", body, err)
		}
	}
	if _, err := parseProfile(401, []byte(`{"id": 1, "login": "a"}`)); !errors.Is(err, errProvider) {
		t.Error("status 401 accepted")
	}
	p, err := parseProfile(200, []byte(`{"id": 123456789012345678901234567890, "login": "big", "name": 5, "id": 9}`))
	if err != nil || p.UserID != "9" || p.DisplayName != "" {
		t.Fatalf("last member wins, any name type dropped: %+v %v", p, err)
	}
	if p, err := parseProfile(200, []byte(`{"id": 123456789012345678901234567890, "login": "big"}`)); err != nil || p.UserID != "123456789012345678901234567890" {
		t.Fatalf("large id: %+v %v", p, err)
	}
}

func TestOrganizationPolicy(t *testing.T) {
	t.Parallel()
	gh := newFakeGitHub(t)
	c := gh.client()
	gh.mu.Lock()
	gh.tokens["t-alice"], gh.tokens["t-bob"], gh.tokens["t-carol"] = "octo-alice", "octo-bob", "octo-carol"
	gh.mu.Unlock()
	cases := []struct {
		token string
		orgs  []string
		want  error
	}{
		{"t-alice", nil, nil},
		{"t-alice", []string{"lab-org"}, nil},
		{"t-bob", []string{"lab-org"}, errOrganization},
		{"t-carol", []string{"lab-org"}, errOrganization},
		{"t-alice", []string{"flaky-org"}, errProvider},
		{"t-alice", []string{"flaky-org", "lab-org"}, nil},
		{"t-bob", []string{"flaky-org", "lab-org"}, errProvider},
		{"t-carol", []string{"other-org", "lab-org"}, errOrganization},
		{"t-unknown", []string{"lab-org"}, errProvider},
	}
	for _, tc := range cases {
		err := c.EnforceOrganizations(t.Context(), tc.token, tc.orgs)
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s %v: %v, want %v", tc.token, tc.orgs, err, tc.want)
		}
	}
}

func TestExchangeRefusals(t *testing.T) {
	t.Parallel()
	gh := newFakeGitHub(t)
	c := gh.client()
	if _, err := c.Exchange(t.Context(), gh.clientID, gh.clientSecret, testRedirect, "", "v"); !errors.Is(err, errProvider) {
		t.Fatal("empty code")
	}
	if _, err := c.Exchange(t.Context(), gh.clientID, gh.clientSecret, testRedirect, strings.Repeat("a", 1025), "v"); !errors.Is(err, errProvider) {
		t.Fatal("long code")
	}
	code := gh.issue("octo-alice", testRedirect, "challenge")
	if _, err := c.Exchange(t.Context(), gh.clientID, "wrong-secret-xxxxxxxxxxxx", testRedirect, code, "v"); !errors.Is(err, errProvider) {
		t.Fatal("wrong client secret")
	}
	if gh.calls["/login/oauth/access_token"] != 1 {
		t.Fatalf("calls %v", gh.calls)
	}
}

func TestAuthorizationURL(t *testing.T) {
	t.Parallel()
	c := Client{}
	got := c.AuthorizationURL("Iv1.abc", testRedirect, "st", "ch")
	want := "https://github.com/login/oauth/authorize?client_id=Iv1.abc&redirect_uri=https%3A%2F%2Fssh.example.test%2Fauth%2Fgithub%2Fcallback&state=st&code_challenge=ch&code_challenge_method=S256"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
