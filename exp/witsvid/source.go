package witsvid

import (
	"context"
	"crypto"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Params are WIT-SVID parameters used when fetching a new WIT-SVID
type Params struct {
	Audience       string
	ExtraAudiences []string
	Subject        spiffeid.ID
	// PublicKey is the workload-owned public key to
	// bind to the WIT-SVID via the cnf.jwk claim
	PublicKey crypto.PublicKey
}

// Source represents a source of WIT-SVIDs
type Source interface {
	// FetchWITSVID fetches a WIT-SVID from the source with the given parameters
	FetchWITSVID(ctx context.Context, params Params) (*SVID, error)
}
