package cmd

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/blockchain-maxis/signet/cli/internal/exitcode"
)

// secretPattern matches a Stellar StrKey secret seed (S... ed25519 secret
// key) — the shape nothing this CLI does should ever print, to stdout,
// stderr, or an error string. Nothing here handles real key material yet
// (see internal/keys), but this is a regression guard for when it does.
var secretPattern = regexp.MustCompile(`\bS[A-Z2-7]{55}\b`)

// assertNoSecretShapedOutput fails t if either buffer contains something
// shaped like a Stellar secret key.
func assertNoSecretShapedOutput(t *testing.T, label string, stdout, stderr *bytes.Buffer) {
	t.Helper()
	if m := secretPattern.FindString(stdout.String()); m != "" {
		t.Fatalf("%s: a secret-shaped value reached stdout: %q", label, m)
	}
	if m := secretPattern.FindString(stderr.String()); m != "" {
		t.Fatalf("%s: a secret-shaped value reached stderr: %q", label, m)
	}
}

func TestNoSecretShapedValueEverReachesOutput(t *testing.T) {
	isolateConfigDir(t)

	// A deliberately secret-key-shaped string fed in as if it were a public
	// key, an identity name, or a URL — every place user-controlled input
	// flows through the command tree. None of these are valid inputs (the
	// pattern doesn't have a 'G' prefix where a public key is expected), so
	// each run is expected to fail; the only thing under test is that the
	// bogus value, and nothing resembling a real secret, ever appears in
	// what the CLI printed.
	poison := "SASAAEJC6P5UZGRLYJ2I2KYLR7RXGF44JZXDYGCFBN7T5VIHECUUEMCD"

	cases := [][]string{
		{"link", "aquawolf", "--public-key", poison},
		{"link", "aquawolf", "--public-key", poison, "--json"},
		{"link", poison, "--public-key", "GASAAEJC6P5UZGRLYJ2I2KYLR7RXGF44JZXDYGCFBN7T5VIHECUUEMCD"},
		{"--source", poison},
		{"--url", poison, "link", "aquawolf", "--public-key", poison},
	}

	for _, args := range cases {
		root := newRootCmd("dev", "none")
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		root.SetOut(stdout)
		root.SetErr(stderr)
		root.SetArgs(args)

		err := root.Execute()

		assertNoSecretShapedOutput(t, "args="+args[0], stdout, stderr)

		// The command tree runs with SilenceErrors, so a returned error never
		// reaches the buffers above — cmd/signet/main.go is what prints it, to
		// the process's real stderr. Checking only the buffers would therefore
		// pass even if the message echoed the value straight back, so the
		// error string is asserted separately. This is the case that matters:
		// a user who puts a secret seed in --public-key by mistake must not
		// have it read back to them (and into their shell history and CI log).
		if err != nil {
			if m := secretPattern.FindString(err.Error()); m != "" {
				t.Fatalf("args=%v: a secret-shaped value reached the error string: %q", args, m)
			}
		}
	}

	// #602: `stellar tx sign`'s stderr is passed into the error, because it is
	// usually the actionable part of a signing failure — and it can echo key
	// material back. A real `signet unlink` runs against a fake `stellar`
	// whose `leaky` identity fails to sign with a secret-shaped string on
	// stderr; that string must not survive into anything the CLI prints.
	t.Run("signing failure", func(t *testing.T) {
		t.Setenv("PATH", fakeStellarDir(t)+string(os.PathListSeparator)+os.Getenv("PATH"))

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/auth/sep10" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("content-type", "application/json")
			_, _ = io.WriteString(w, `{"transaction":"AAAAunsignedchallengeAAAA","network_passphrase":"Test SDF Network ; September 2015"}`)
		}))
		defer srv.Close()

		root := newRootCmd("dev", "none")
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		root.SetOut(stdout)
		root.SetErr(stderr)
		root.SetArgs([]string{"unlink", "--yes", "--source", "leaky", "--url", srv.URL})

		err := root.Execute()

		// Reaching signing is what makes this case mean anything: a run that
		// failed earlier (no stellar on PATH, a bad flag) would pass the leak
		// checks below without exercising the stderr path at all.
		if !errors.Is(err, exitcode.ErrSigningFailure) {
			t.Fatalf("err = %v, want a signing failure from `stellar tx sign`", err)
		}
		assertNoSecretShapedOutput(t, "unlink signing failure", stdout, stderr)
		if m := secretPattern.FindString(err.Error()); m != "" {
			t.Fatalf("a secret-shaped value from stellar's stderr reached the error string: %q", m)
		}
		// Redacted, not dropped: the rest of stellar's message is still there.
		if !strings.Contains(err.Error(), "could not decode signing key") {
			t.Fatalf("stellar's stderr was lost rather than redacted: %v", err)
		}
	})
}

// fakeStellarDir builds internal/keys/testdata/fakestellar as `stellar` in a
// temp dir and returns that dir, for putting first on PATH — the commands
// resolve `stellar` by name, exactly as they would the real one. Skips when
// no Go toolchain is on PATH, as internal/keys' own helper does.
func fakeStellarDir(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain to build the fake stellar: %v", err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "stellar")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	build := exec.Command(goBin, "build", "-o", out, "../keys/testdata/fakestellar")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the fake stellar: %v\n%s", err, output)
	}
	return dir
}
