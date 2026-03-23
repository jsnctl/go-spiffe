package witsvid

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/witbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var allowedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}

// tokenValidator validates the token and returns the claims
type tokenValidator = func(*jwt.JSONWebToken, spiffeid.TrustDomain) (map[string]interface{}, error)

// cnfClaim represents the confirmation claim
type cnfClaim struct {
	JWK *jose.JSONWebKey `json:"jwk"`
}

// parsedClaims is used for unmarshaling the full WIT claims payload
type parsedClaims struct {
	jwt.Claims
	CNF *cnfClaim `json:"cnf"`
}

// SVID represents a WIT-SVID
type SVID struct {
	// ID is the SPIFFE ID of the WIT-SVID as present in the 'sub' claim
	ID spiffeid.ID
	// Audience is the intended recipients of WIT-SVID as present in the 'aud' claim
	Audience []string
	// Expiry is the expiration time of WIT-SVID as present in the 'exp' claim
	Expiry time.Time
	// IssuedAt is the issuance time of WIT-SVID as present in the 'iat' claim
	IssuedAt time.Time
	// PublicKey is the workload-owned public key bound to this WIT-SVID via
	// the 'cnf.jwk' claim
	PublicKey crypto.PublicKey
	// Claims contains all parsed claims from the token payload
	Claims map[string]interface{}
	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned
	Hint string

	// token is the serialized WIT token
	token string
}

// ParseAndValidate parses and validates a WIT-SVID token and returns the
// WIT-SVID. The WIT-SVID signature is verified using the WIT bundle source.
func ParseAndValidate(token string, bundles witbundle.Source, audience []string) (*SVID, error) {
	return parse(token, audience, func(tok *jwt.JSONWebToken, trustDomain spiffeid.TrustDomain) (map[string]interface{}, error) {
		keyID := tok.Headers[0].KeyID
		if keyID == "" {
			return nil, wrapWitsvidErr(errors.New("token header missing key id"))
		}

		bundle, err := bundles.GetWITBundleForTrustDomain(trustDomain)
		if err != nil {
			return nil, wrapWitsvidErr(fmt.Errorf("no bundle found for trust domain %q", trustDomain))
		}

		authority, ok := bundle.FindWITAuthority(keyID)
		if !ok {
			return nil, wrapWitsvidErr(fmt.Errorf("no WIT authority %q found for trust domain %q", keyID, trustDomain))
		}

		claimsMap := make(map[string]interface{})
		if err := tok.Claims(authority, &claimsMap); err != nil {
			return nil, wrapWitsvidErr(fmt.Errorf("unable to get claims from token: %v", err))
		}

		return claimsMap, nil
	})
}

// ParseInsecure parses and validates a WIT-SVID token and returns the
// WIT-SVID. The WIT-SVID signature is not verified
func ParseInsecure(token string, audience []string) (*SVID, error) {
	return parse(token, audience, func(tok *jwt.JSONWebToken, td spiffeid.TrustDomain) (map[string]interface{}, error) {
		claimsMap := make(map[string]interface{})
		if err := tok.UnsafeClaimsWithoutVerification(&claimsMap); err != nil {
			return nil, wrapWitsvidErr(fmt.Errorf("unable to get claims from token: %v", err))
		}
		return claimsMap, nil
	})
}

// Marshal returns the WIT-SVID serialized to a string. The returned value is
// the same token value originally passed to ParseAndValidate or ParseInsecure.
func (svid *SVID) Marshal() string {
	return svid.token
}

func parse(token string, audience []string, getClaims tokenValidator) (*SVID, error) {
	tok, err := jwt.ParseSigned(token, allowedSignatureAlgorithms)
	if err != nil {
		return nil, wrapWitsvidErr(errors.New("unable to parse WIT token"))
	}

	// WIT tokens MUST have typ == "wit+jwt" as required by the specification
	typ, _ := tok.Headers[0].ExtraHeaders[jose.HeaderType]
	if typ != "wit+jwt" {
		return nil, wrapWitsvidErr(errors.New(`token header type must be "wit+jwt"`))
	}

	// Parse (unverified) claims to get the trust domain of the SPIFFE ID
	var claims parsedClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, wrapWitsvidErr(fmt.Errorf("unable to get claims from token: %v", err))
	}

	switch {
	case claims.Subject == "":
		return nil, wrapWitsvidErr(errors.New("token missing subject claim"))
	case claims.Expiry == nil:
		return nil, wrapWitsvidErr(errors.New("token missing exp claim"))
	}

	spiffeID, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return nil, wrapWitsvidErr(fmt.Errorf("token has an invalid subject claim: %v", err))
	}

	// Create generic map of claims
	claimsMap, err := getClaims(tok, spiffeID.TrustDomain())
	if err != nil {
		return nil, err
	}

	// NOTE: WIT-specific (when compared to JWT-SVID)
	// Validate the cnf.jwk claim
	if claims.CNF == nil || claims.CNF.JWK == nil {
		return nil, wrapWitsvidErr(errors.New("token missing cnf.jwk claim"))
	}
	if !claims.CNF.JWK.Valid() {
		return nil, wrapWitsvidErr(errors.New("token cnf.jwk is invalid"))
	}

	// Validate standard claims
	if err := claims.Claims.Validate(jwt.Expected{
		AnyAudience: audience,
		Time:        time.Now(),
	}); err != nil {
		switch err {
		case jwt.ErrExpired:
			err = wrapWitsvidErr(errors.New("token has expired"))
		case jwt.ErrInvalidAudience:
			err = wrapWitsvidErr(fmt.Errorf("expected audience in %q (audience=%q)", audience, claims.Audience))
		}
		return nil, err
	}

	var issuedAt time.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time().UTC()
	}

	return &SVID{
		ID:        spiffeID,
		Audience:  claims.Audience,
		Expiry:    claims.Expiry.Time().UTC(),
		IssuedAt:  issuedAt,
		PublicKey: claims.CNF.JWK.Public().Key,
		Claims:    claimsMap,
		token:     token,
	}, nil
}

func wrapWitsvidErr(err error) error {
	return fmt.Errorf("witsvid: %w", err)
}
