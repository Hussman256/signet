// Command fakestellar is a stand-in for the real `stellar` CLI, used by
// keys_test.go and by internal/cmd's secret-leak test. It understands the
// invocations ResolvePublicKey, CheckStellarCLI and SignChallenge make —
// `stellar keys address <name>`, `stellar --version` and
// `stellar tx sign --sign-with-key <name> …` — and its behavior is chosen by
// the requested name (or the FAKESTELLAR_VERSION env var, for --version), so
// tests don't need to build multiple binaries.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// leakedSecret is what the `leaky` identity's failed `tx sign` puts on stderr:
// a secret-shaped value, the case #602 redacts before stellar's stderr goes
// into an error. Not a real key.
const leakedSecret = "SASAAEJC6P5UZGRLYJ2I2KYLR7RXGF44JZXDYGCFBN7T5VIHECUUEMCD"

func main() {
	args := os.Args[1:]

	if len(args) >= 2 && args[0] == "tx" && args[1] == "sign" {
		txSign(args[2:])
		return
	}

	if len(args) == 2 && args[0] == "keys" && args[1] == "ls" {
		// Newline-separated identity names, as `stellar keys ls` prints them.
		// Empty (or unset) means a keystore with no identities at all.
		for _, name := range strings.Split(os.Getenv("FAKESTELLAR_IDENTITIES"), "\n") {
			if strings.TrimSpace(name) != "" {
				fmt.Println(strings.TrimSpace(name))
			}
		}
		return
	}

	if len(args) == 1 && args[0] == "--version" {
		version := os.Getenv("FAKESTELLAR_VERSION")
		if version == "" {
			version = "25.2.0"
		}
		fmt.Printf("stellar %s\n", version)
		return
	}

	if len(args) != 3 || args[0] != "keys" || args[1] != "address" {
		fmt.Fprintln(os.Stderr, "fakestellar: unsupported invocation")
		os.Exit(2)
	}

	switch args[2] {
	case "alice":
		fmt.Println("GASAAEJC6P5UZGRLYJ2I2KYLR7RXGF44JZXDYGCFBN7T5VIHECUUEMCD")
	case "bob":
		fmt.Println("GBVBJEP2BSKHW6YBFCZR2HJKHZDLJOU7ZKTH2HSNUUQY322RWLURH3EQ")
	case "leaky":
		fmt.Println("GBVBJEP2BSKHW6YBFCZR2HJKHZDLJOU7ZKTH2HSNUUQY322RWLURH3EQ")
	case "garbage":
		fmt.Println("not-a-public-key")
	case "missing":
		fmt.Fprintln(os.Stderr, `no identity named "missing"`)
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "fakestellar: unknown identity")
		os.Exit(1)
	}
}

// txSign mimics `stellar tx sign --sign-with-key <name> --network-passphrase
// <p>` reading the envelope from stdin. The `leaky` identity fails the way a
// misconfigured keystore might, echoing key material into its stderr; any
// other identity "signs" by returning a fixed envelope.
func txSign(flags []string) {
	var identity string
	for i := 0; i+1 < len(flags); i++ {
		if flags[i] == "--sign-with-key" {
			identity = flags[i+1]
		}
	}
	if _, err := io.ReadAll(os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "fakestellar: reading stdin:", err)
		os.Exit(2)
	}
	if identity == "leaky" {
		fmt.Fprintf(os.Stderr, "error: could not decode signing key %s for this network\n", leakedSecret)
		os.Exit(1)
	}
	fmt.Println("AAAAAgAAAABxdnhrZmFrZXNpZ25lZGVudmVsb3BlAAAAAAAAZA==")
}
