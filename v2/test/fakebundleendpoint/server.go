package fakebundleendpoint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
)

type FakeBundleEndpointProvider struct {
	tb         testing.TB
	wg         sync.WaitGroup
	addr       net.Addr
	httpServer *http.Server
	// Root certificates used by clients to verify server certificates.
	rootCAs *x509.CertPool
	// TLS configuration used by the server.
	tlscfg *tls.Config
	// SPIFFE bundles that can be returned by this Server.
	bundles []*spiffebundle.Bundle
}

type FakeBundleEndpointProviderOption interface {
	apply(*FakeBundleEndpointProvider)
}

func New(tb testing.TB, option ...FakeBundleEndpointProviderOption) *FakeBundleEndpointProvider {
	rootCAs, cert := test.CreateWebCredentials(tb)
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	fbep := &FakeBundleEndpointProvider{
		tb:      tb,
		rootCAs: rootCAs,
		tlscfg:  tlscfg,
	}

	for _, opt := range option {
		opt.apply(fbep)
	}

	sm := http.NewServeMux()
	sm.HandleFunc("/test-bundle", fbep.testbundle)
	fbep.httpServer = &http.Server{
		Handler:           sm,
		TLSConfig:         fbep.tlscfg,
		ReadHeaderTimeout: time.Second * 10,
	}
	err := fbep.start()
	if err != nil {
		tb.Fatalf("Failed to start: %v", err)
	}
	return fbep
}

func (s *FakeBundleEndpointProvider) Shutdown() {
	err := s.httpServer.Shutdown(context.Background())
	assert.NoError(s.tb, err)
	s.wg.Wait()
}

func (s *FakeBundleEndpointProvider) Addr() string {
	return s.addr.String()
}

func (s *FakeBundleEndpointProvider) FetchBundleURL() string {
	return fmt.Sprintf("https://%s/test-bundle", s.Addr())
}

func (s *FakeBundleEndpointProvider) RootCAs() *x509.CertPool {
	return s.rootCAs
}

func (s *FakeBundleEndpointProvider) start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return err
	}

	s.addr = ln.Addr()

	s.wg.Add(1)
	go func() {
		err := s.httpServer.ServeTLS(ln, "", "")
		assert.EqualError(s.tb, err, http.ErrServerClosed.Error())
		s.wg.Done()
		ln.Close()
	}()
	return nil
}

func (s *FakeBundleEndpointProvider) testbundle(w http.ResponseWriter, r *http.Request) {
	if len(s.bundles) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	bb, err := s.bundles[0].Marshal()
	assert.NoError(s.tb, err)
	s.bundles = s.bundles[1:]
	w.Header().Add("Content-Type", "application/json")
	b, err := w.Write(bb)
	assert.NoError(s.tb, err)
	assert.Equal(s.tb, len(bb), b)
}

type fakeOption func(*FakeBundleEndpointProvider)

// WithTestBundles sets the bundles that are returned by the Bundle Endpoint. You can
// specify several bundles, which are going to be returned one at a time each time
// a bundle is GET by a client.
func WithTestBundles(bundles ...*spiffebundle.Bundle) FakeBundleEndpointProviderOption {
	return fakeOption(func(s *FakeBundleEndpointProvider) {
		s.bundles = bundles
	})
}

func WithSPIFFEAuth(bundle *spiffebundle.Bundle, svid *x509svid.SVID) FakeBundleEndpointProviderOption {
	return fakeOption(func(s *FakeBundleEndpointProvider) {
		s.rootCAs = x509util.NewCertPool(bundle.X509Authorities())
		s.tlscfg = tlsconfig.TLSServerConfig(svid)
	})
}

func (fo fakeOption) apply(s *FakeBundleEndpointProvider) {
	fo(s)
}
