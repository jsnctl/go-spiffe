package witsvid_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/witsvid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	bundleKey, _   = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	workloadKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
)

type witTokenClaims struct {
	jwt.Claims
	CNF map[string]interface{} `json:"cnf,omitempty"`
}

func TestParseAndValidate(t *testing.T) {
	issuedAt := jwt.NewNumericDate(time.Now())
	expiresTime := time.Now().Add(time.Minute)
	expires := jwt.NewNumericDate(expiresTime)

	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/workload")

	bundle := witbundle.New(td)
	require.NoError(t, bundle.AddWITAuthority("key-1", bundleKey.Public()))

	testCases := []struct {
		name          string
		bundle        *witbundle.Bundle
		audience      []string
		generateToken func(testing.TB) string
		err           string
		svid          *witsvid.SVID
	}{
		{
			name:     "success",
			bundle:   bundle,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Issuer:   "spiffe://example.org",
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			svid: &witsvid.SVID{
				ID:       id,
				Audience: []string{"audience"},
				Expiry:   expiresTime,
			},
		},
		{
			name:   "malformed token",
			bundle: bundle,
			generateToken: func(tb testing.TB) string {
				return "not.a.token"
			},
			err: "witsvid: unable to parse WIT token",
		},
		{
			name:   "wrong typ header",
			bundle: bundle,
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				// Generate a JWT-SVID-style token (typ: JWT) instead of wit+jwt
				return generateTokenWithTyp(tb, claims, workloadKey.Public(), bundleKey, "key-1", "JWT")
			},
			err: `witsvid: token header type must be "wit+jwt"`,
		},
		{
			name:   "missing subject",
			bundle: bundle,
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			err: "witsvid: token missing subject claim",
		},
		{
			name:   "missing expiry",
			bundle: bundle,
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			err: "witsvid: token missing exp claim",
		},
		{
			name:   "invalid subject claim",
			bundle: bundle,
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  "not-a-spiffe-id",
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			err: "witsvid: token has an invalid subject claim: scheme is missing or invalid",
		},
		{
			name:     "missing key id",
			bundle:   bundle,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "")
			},
			err: "witsvid: token header missing key id",
		},
		{
			name:     "no bundle for trust domain",
			bundle:   bundle,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  "spiffe://other.domain/workload",
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			err: `witsvid: no bundle found for trust domain "other.domain"`,
		},
		{
			name:     "unknown authority",
			bundle:   bundle,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "unknown-key")
			},
			err: `witsvid: no WIT authority "unknown-key" found for trust domain "example.org"`,
		},
		{
			name:     "missing cnf claim",
			bundle:   bundle,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, nil, bundleKey, "key-1")
			},
			err: "witsvid: token missing cnf.jwk claim",
		},
		{
			name:     "expired",
			bundle:   bundle,
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   jwt.NewNumericDate(time.Now().Add(-time.Minute)),
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			err: "witsvid: token has expired",
		},
		{
			name:     "unexpected audience",
			bundle:   bundle,
			audience: []string{"other"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			err: `witsvid: expected audience in ["other"] (audience=["audience"])`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.generateToken(t)
			svid, err := witsvid.ParseAndValidate(token, tc.bundle, tc.audience)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.svid.ID, svid.ID)
			require.Equal(t, tc.svid.Expiry.Unix(), svid.Expiry.Unix())
			require.Equal(t, tc.svid.Audience, svid.Audience)
			require.NotNil(t, svid.PublicKey)
		})
	}
}

func TestParseInsecure(t *testing.T) {
	issuedAt := jwt.NewNumericDate(time.Now())
	expiresTime := time.Now().Add(time.Minute)
	expires := jwt.NewNumericDate(expiresTime)

	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/workload")

	testCases := []struct {
		name          string
		audience      []string
		generateToken func(testing.TB) string
		err           string
		svid          *witsvid.SVID
	}{
		{
			name:     "success",
			audience: []string{"audience"},
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
					IssuedAt: issuedAt,
				}
				return generateWIT(tb, claims, workloadKey.Public(), bundleKey, "key-1")
			},
			svid: &witsvid.SVID{
				ID:       id,
				Audience: []string{"audience"},
				Expiry:   expiresTime,
			},
		},
		{
			name: "wrong typ header",
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
				}
				return generateTokenWithTyp(tb, claims, workloadKey.Public(), bundleKey, "key-1", "JWT")
			},
			err: `witsvid: token header type must be "wit+jwt"`,
		},
		{
			name: "missing cnf claim",
			generateToken: func(tb testing.TB) string {
				claims := jwt.Claims{
					Subject:  id.String(),
					Expiry:   expires,
					Audience: jwt.Audience{"audience"},
				}
				return generateWIT(tb, claims, nil, bundleKey, "key-1")
			},
			err: "witsvid: token missing cnf.jwk claim",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.generateToken(t)
			svid, err := witsvid.ParseInsecure(token, tc.audience)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.svid.ID, svid.ID)
			require.Equal(t, tc.svid.Expiry.Unix(), svid.Expiry.Unix())
			require.Equal(t, tc.svid.Audience, svid.Audience)
			require.NotNil(t, svid.PublicKey)
		})
	}
}

func TestMarshal(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	id := spiffeid.RequireFromPath(td, "/workload")

	claims := jwt.Claims{
		Subject:  id.String(),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Minute)),
		Audience: jwt.Audience{"audience"},
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	token := generateWIT(t, claims, workloadKey.Public(), bundleKey, "key-1")

	svid, err := witsvid.ParseInsecure(token, []string{"audience"})
	require.NoError(t, err)
	require.Equal(t, token, svid.Marshal())

	// Mutating the SVID does not affect the marshaled token
	svid.ID = spiffeid.RequireFromPath(td, "/other")
	require.Equal(t, token, svid.Marshal())

	// Empty SVID marshals to empty string
	require.Empty(t, (&witsvid.SVID{}).Marshal())
}

func generateWIT(tb testing.TB, claims jwt.Claims, cnfKey crypto.PublicKey, signer crypto.Signer, keyID string) string {
	return generateTokenWithTyp(tb, claims, cnfKey, signer, keyID, "wit+jwt")
}

// generateTokenWithTyp is a helper fn to generate a token with a specificed typ header
// Useful for testing header validation (e.g. incompliant cases)
func generateTokenWithTyp(tb testing.TB, claims jwt.Claims, cnfKey crypto.PublicKey, signer crypto.Signer, keyID string, typ string) string {
	tb.Helper()

	options := new(jose.SignerOptions).WithHeader(jose.HeaderType, typ)
	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(signer),
				KeyID: keyID,
			},
		},
		options,
	)
	require.NoError(tb, err)

	fullClaims := witTokenClaims{Claims: claims}
	if cnfKey != nil {
		jwk := jose.JSONWebKey{Key: cnfKey, Algorithm: string(jose.ES256)}
		jwkBytes, err := jwk.MarshalJSON()
		require.NoError(tb, err)
		var jwkMap map[string]interface{}
		require.NoError(tb, json.Unmarshal(jwkBytes, &jwkMap))
		fullClaims.CNF = map[string]interface{}{"jwk": jwkMap}
	}

	token, err := jwt.Signed(jwtSigner).Claims(fullClaims).Serialize()
	require.NoError(tb, err)
	return token
}
