//go:build linux && !race

// The race detector multiplies the memory of every allocation, so the
// measurement runs only in a normal build.

package main

import (
	"bufio"
	json "encoding/json/v2"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const k10MemoryEnv = "WEBSSH_K10_MEMORY_IN"

// memLimit is the default mem_limit of docker-compose.hardened.yml
// (WEBSSH_MEMORY_LIMIT, 2g).
const memLimit = 2 << 30

// peakBound is what the peak may reach: the migration handles one
// account at a time, so the peak depends on the largest account's stores
// and not on the number of accounts. Two accounts with these stores peak
// at about 820 MiB, ten at about 845 MiB; reading every account before
// writing took more than 2 GiB from seven accounts on.
const peakBound = 1280 << 20

// TestK10MemoryHelper migrates the DATA_DIR named by the environment with
// the build's registry and prints the peak resident set size.
func TestK10MemoryHelper(t *testing.T) {
	dir := os.Getenv(k10MemoryEnv)
	if dir == "" {
		t.Skip("helper process for the K10 memory test")
	}
	_, lookup := k10Env(t, dir)
	log := slog.New(slog.DiscardHandler)
	cfg, err := bootstrapConfig(lookup, log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := startMigration(t.Context(), cfg, lookup, log)
	result := "error: " + fmt.Sprint(err)
	if err == nil {
		result = fmt.Sprintf("state %s migrated %v", st.State, st.Migrated)
		_ = st.Close()
	}
	fmt.Printf("K10MEM %d %s\n", peakRSS(t), result)
}

// peakRSS is VmHWM of this process in bytes.
func peakRSS(t *testing.T) int64 {
	t.Helper()
	f, err := os.Open("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "VmHWM:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "kB")), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return kb << 10
		}
	}
	t.Fatal("no VmHWM")
	return 0
}

// bigStore writes a profile or jump host store of size bytes, just below
// the 64 MiB read limit: records with a long unknown field, which the
// migration keeps (SOCKS proxies take no unknown fields).
func bigStore(t *testing.T, path, listKey string, version, records, size int) {
	t.Helper()
	pad := strings.Repeat("x", size/records-512)
	list := make([]map[string]any, records)
	for i := range list {
		r := map[string]any{"id": fmt.Sprintf("00000000-0000-4000-8000-%012d", i), "name": fmt.Sprintf("big %d", i),
			"host": fmt.Sprintf("big-%d.example.test", i), "port": 22, "username": "u", "legacy_padding": pad}
		switch listKey {
		case "profiles":
			r["auth_type"], r["key_id"], r["startup_mode"], r["sort_order"] = "password", nil, "none", i
		case "jump_hosts":
			r["auth_type"], r["key_id"] = "password", nil
		}
		list[i] = r
	}
	data, err := json.Marshal(map[string]any{"schema_version": version, listKey: list})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The peak memory of a migration of ten accounts whose per-user stores
// sit just below the 64 MiB read limit stays well below the container's
// mem_limit (M2 MG1 DoD, MG1-1). The migration may stop on such stores (Python refuses stores
// above its connection limit); what counts is that the reading never
// takes the process near the limit.
func TestBuildMigrationMemoryWithLargeStores(t *testing.T) {
	if testing.Short() {
		t.Skip("writes about 1.3 GiB of legacy stores")
	}
	dir := extractGolden(t, "datadir-extended.tar")
	const size = 63 << 20
	for _, user := range k10MemoryUsers() {
		d := filepath.Join(dir, "users", user)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		bigStore(t, filepath.Join(d, "profiles.json"), "profiles", 3, 400, size)
		bigStore(t, filepath.Join(d, "jump_hosts.json"), "jump_hosts", 2, 100, size)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestK10MemoryHelper$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), k10MemoryEnv+"="+dir)
	cmd.Env = append(cmd.Env, helperTempDir(t)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	var peak int64
	var result string
	for line := range strings.Lines(string(out)) {
		if rest, ok := strings.CutPrefix(line, "K10MEM "); ok {
			n, r, _ := strings.Cut(strings.TrimSpace(rest), " ")
			peak, _ = strconv.ParseInt(n, 10, 64)
			result = r
		}
	}
	if peak == 0 {
		t.Fatalf("no measurement:\n%s", out)
	}
	t.Logf("peak RSS %d MiB, %s", peak>>20, result)
	if peak >= peakBound {
		t.Fatalf("peak RSS %d MiB with %d accounts above %d MiB (mem_limit %d MiB)", peak>>20, len(k10MemoryUsers()), peakBound>>20, memLimit>>20)
	}
}

// k10MemoryUsers are the accounts that get the large stores.
func k10MemoryUsers() []string {
	n, _ := strconv.Atoi(os.Getenv("WEBSSH_K10_MEMORY_USERS"))
	if n == 0 {
		n = 10
	}
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("user_%d", 3+i)
	}
	return out
}
