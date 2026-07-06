// Package nsbox is the Linux namespace backend. The parent clones hako
// into fresh user/mount/pid/uts/ipc (and optionally net) namespaces via
// the shim; the init stage in this package builds a minimal root from
// the policy's bind allowlist and pivots into it.
package nsbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tamnd/hako/pkg/policy"
)

// EnvSpec carries the encoded Spec from parent to init stage.
const EnvSpec = "HAKO_SPEC"

// Spec is everything the init stage needs, serialized into one env var.
type Spec struct {
	Argv   []string
	Dir    string
	Env    []string
	Read   []string
	Write  []string
	Deny   []string
	Net    bool
	Limits policy.Limits
}

// Encode packs the spec for the EnvSpec variable.
func (s *Spec) Encode() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// DecodeEnv reads the spec back in the init stage.
func DecodeEnv() (*Spec, error) {
	raw := os.Getenv(EnvSpec)
	if raw == "" {
		return nil, fmt.Errorf("%s not set", EnvSpec)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
