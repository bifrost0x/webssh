# Third-party Go forks

Code in this directory is maintained outside the main module. Each fork is
its own Go module under its upstream module path and is bound to this
directory by a `replace` directive in the root `go.mod`, so import paths
stay the upstream ones and local patches can be offered upstream unchanged.
The architecture tests (`internal/architecture/forks_test.go`) accept only
such replace directives and pin the module path, the license file, the
modules each fork may link and the fork packages WebSSH must not import.

## go-smb2

SMB 2/3 client for the SMB file backend (`internal/files/smb`).

| | |
|---|---|
| Upstream | <https://github.com/hirochachacha/go-smb2>, module `github.com/hirochachacha/go-smb2/v2` |
| Base | commit `7f69f65878329522ceb556435bdeb3cde6552656`, pseudo-version `v2.0.0-20261011164520-7f69f6587832`, module hash `h1:3YBr27iWTBRKqCbXCSFA7MQrgFOpzZr+Y0ffmErN6CA=` |
| License | BSD-2-Clause, `go-smb2/LICENSE`; notice repeated in `THIRD-PARTY-NOTICES` |
| Linked modules | `github.com/geoffgarside/ber`, `golang.org/x/crypto` (MD4 for NTLM) |
| Not imported by WebSSH | `client`, `dfs` (follow DFS referrals), `user` (LSA lookups) |

The first commit of the fork copies the module zip of the base commit
unchanged, without upstream CI files, contributor tooling and bug-report
notes. Later commits change it in three ways.

**Patch intended for upstream** (`patches/go-smb2-require-encryption.patch`, a
plain diff against the base commit; it applies with `git apply` and its
tests pass on an unchanged upstream checkout):

- `Dialer.RequireEncryption`: every request after session setup is
  encrypted and a plaintext response to it is refused. Setup fails with
  `ErrEncryptionUnavailable` when no cipher was negotiated or the session is
  guest or anonymous; anonymous credentials fail with
  `ErrCredentialsRequired` before a transport is opened.
- `Session.SecurityInfo`, `Share.Info`: negotiated dialect, cipher, signing,
  session and tree flags, DFS.
- `Share.OpenWith`: one CREATE with exact parameters, never following
  symbolic links.

**Removed for WebSSH only:** SMB over QUIC, Kerberos and compression. The
client offers no compression in NEGOTIATE, refuses a server that selects an
algorithm, and refuses compressed packets before decoding them. This takes
quic-go, go-krb5, go-crypt/x, google/uuid, lz4 and x/net out of the build.

**Lab tests for WebSSH:** `go-smb2/lab_test.go` checks the patch against
the WebSSH test lab (`WEBSSH_SMB_LAB=<lab.json>`): encryption of every
message after session setup on Samba shares with and without required
encryption and on Windows Server, no compressed messages, refused empty
and wrong credentials. The integration suite takes `"require_encryption":
true` in the `conn` section of `client_conf.json`.

**Test fixes:** two fake servers in the fork's tests accept CANCEL, which
the client sends for pipelined reads it no longer needs; upstream they fail
intermittently.

### Checks

CI job `smb-fork` in `.github/workflows/go.yml` runs in `go-smb2`:
`go mod tidy -diff`, `go mod verify`, gofmt, `go vet`, staticcheck,
govulncheck and `go test -race ./...`. The fork's integration tests need a
`client_conf.json` (path in `SMB2_CLIENT_CONFIG`) with real servers and
skip without one; they run against the test lab by hand, with
`SMB2_SKIP_DIRECTORY_SYMLINK_SUFFIX=1` for Samba, which does not resolve a
stored symlink in the middle of a path.

gosec is not run on the fork. Its findings there are dominated by integer
conversions in wire decoding and by MD5, RC4 and MD4, which NTLMv2
([MS-NLMP]) requires; changes to the fork are reviewed by hand instead.

### Vulnerability tracking

govulncheck matches advisories by module path. Advisories filed for
`github.com/hirochachacha/go-smb2` (v1) do not name the v2 path, so they
never show up for this fork, even when the code is shared. Before every
release and on every rebase:

1. Search <https://pkg.go.dev/vuln/list> and the upstream issues for
   `go-smb2` (both `hirochachacha` and the `cloudsoda` fork, which shares
   much of the v1 code).
2. For each advisory, check whether the v2 code at the fork's base has the
   flaw, and record the result in the list below.
3. Fix flaws present in the fork with a test, and offer the fix upstream.

| Advisory | Affects | State in the fork |
|---|---|---|
| GO-2026-5051 | `Share.ReadDir` out-of-bounds read and panic on a malicious QUERY_DIRECTORY response; recorded for the v1 path without a fixed version | Not affected: the v2 directory decoders bound NextEntryOffset and FileNameLength (upstream PR #103). Pinned by `TestReaddirMalformedEntriesGO20265051` and upstream's decoder tests and fuzz targets. Checked 2026-11-26. |

### Rebasing onto a newer upstream commit

1. Download the new commit with `go mod download -json
   github.com/hirochachacha/go-smb2/v2@<commit>` and note version and hash.
2. Replace the content of `go-smb2` with the module zip, leaving out the
   same upstream files as before, and commit it unchanged.
3. Reapply the patch, the removals and the test fixes, one commit each, and
   regenerate `patches/go-smb2-require-encryption.patch` from the patch
   commit.
4. Run the `smb-fork` checks, the architecture tests and the lab tests, and
   update the table above, the base in this file and the vulnerability list.
