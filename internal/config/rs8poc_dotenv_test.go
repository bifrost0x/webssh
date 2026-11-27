package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RS8-04: a .env of a few hundred bytes expanded to a value of 2^n bytes,
// although maxDotenvSize bounds only the file. The interpolated values
// are bounded as a whole now, and the file stops the start.
func TestRS8PocDotenvExpansion(t *testing.T) {
	var b strings.Builder
	b.WriteString("V0=xxxxxxxx\n")
	const n = 22
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "V%d=${V%d}${V%d}\n", i, i-1, i-1)
	}
	file := b.String()
	_, _, err := parseDotenv([]byte(file), lookupMap(nil))
	if !errors.Is(err, errDotenvExpansion) {
		t.Fatalf("a %d-byte file expanding past %d bytes: %v", len(file), maxDotenvExpansion, err)
	}
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadDotenv(path, lookupMap(nil)); err == nil || !strings.Contains(err.Error(), "CONFIGURATION ERROR") {
		t.Fatalf("ReadDotenv: %v", err)
	}
}

// Expansion within the bound keeps working, up to the bound exactly.
func TestDotenvExpansionUpToTheBound(t *testing.T) {
	half := strings.Repeat("x", maxDotenvExpansion/4)
	file := "A=" + half + "\nB=${A}\nC=${A}${A}\n" // 4 quarters in total
	got, _, err := parseDotenv([]byte(file), lookupMap(nil))
	if err != nil || len(got) != 3 || len(got[2].Value) != maxDotenvExpansion/2 {
		t.Fatalf("%d assignments, err %v", len(got), err)
	}
	if _, _, err := parseDotenv([]byte(file+"D=y\n"), lookupMap(nil)); !errors.Is(err, errDotenvExpansion) {
		t.Fatalf("one byte past the bound: %v", err)
	}
}

// An unclosed "${" repeated over a long value is scanned in linear time;
// it was scanned to the end of the value once per "${".
func TestDotenvUnclosedVariablesAreLinear(t *testing.T) {
	value := strings.Repeat("${a", 1<<20/3)
	start := time.Now()
	got, _, err := parseDotenv([]byte("K="+value+"\nL=${a${b:-c${d:-e}f\n"), lookupMap(nil))
	if err != nil || len(got) != 2 || got[0].Value != value || got[1].Value != "c${d:-ef" {
		t.Fatalf("err %v, %d assignments, L=%q", err, len(got), got[len(got)-1].Value)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("1 MiB of unclosed variables took %v", d)
	}
}
