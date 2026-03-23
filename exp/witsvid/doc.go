// Package witsvid provides WIT-SVID related functionality
//
// A WIT-SVID is a Workload Identity Token (WIT) as defined by the IETF WIMSE
// working group. Unlike a JWT-SVID (a bearer token), a WIT binds a
// workload-owned public key to the SPIFFE identity via the 'cnf.jwk' claim
// (RFC 7800). The workload retains the corresponding private key and uses it
// to produce proof-of-possession when authenticating
//
// Parsing a WIT-SVID with signature verification:
//
//	var bundles witbundle.Source = ...
//	svid, err := witsvid.ParseAndValidate(token, bundles, []string{"audience"})
//
// Parsing a WIT-SVID without signature verification:
//
//	svid, err := witsvid.ParseInsecure(token, []string{"audience"})
//
// After parsing, the bound public key is available in the SVID:
//
//	publicKey := svid.PublicKey
package witsvid
