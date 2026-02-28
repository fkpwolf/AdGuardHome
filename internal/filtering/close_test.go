package filtering_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/hashprefix"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDNSFilter_Close_ClosesCheckers verifies that the DNSFilter.Close() method
// properly closes the SafeBrowsingChecker and ParentalControlChecker to prevent
// HTTPS connection leaks.
func TestDNSFilter_Close_ClosesCheckers(t *testing.T) {
	// Track Close calls on the mock upstream
	var sbCloseCalled, pcCloseCalled bool
	
	// Create mock upstreams that track Close calls
	sbUpstream := aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
		return &dns.Msg{}, nil
	})
	sbUpstream.OnClose = func() error {
		sbCloseCalled = true
		return nil
	}
	
	pcUpstream := aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
		return &dns.Msg{}, nil
	})
	pcUpstream.OnClose = func() error {
		pcCloseCalled = true
		return nil
	}

	// Create checkers with the mock upstreams
	sbChecker := hashprefix.New(&hashprefix.Config{
		Logger:    slogutil.NewDiscardLogger(),
		Upstream:  sbUpstream,
		TXTSuffix: "sb.dns.test",
		CacheTime: 0,
		CacheSize: 0,
	})
	
	pcChecker := hashprefix.New(&hashprefix.Config{
		Logger:    slogutil.NewDiscardLogger(),
		Upstream:  pcUpstream,
		TXTSuffix: "pc.dns.test",
		CacheTime: 0,
		CacheSize: 0,
	})

	// Create DNSFilter with the checkers
	dnsFilter, err := filtering.New(&filtering.Config{
		Logger:                  slogutil.NewDiscardLogger(),
		SafeBrowsingChecker:     sbChecker,
		ParentalControlChecker:  pcChecker,
		SafeBrowsingEnabled:     true,
		ParentalEnabled:         true,
		ProtectionEnabled:       true,
	}, nil)
	require.NoError(t, err)

	// Verify Close is not called initially
	assert.False(t, sbCloseCalled, "SafeBrowsing Close should not be called initially")
	assert.False(t, pcCloseCalled, "ParentalControl Close should not be called initially")

	// Close the DNSFilter
	dnsFilter.Close()

	// Verify that Close was called on both checkers
	assert.True(t, sbCloseCalled, "SafeBrowsing Close should be called when DNSFilter is closed")
	assert.True(t, pcCloseCalled, "ParentalControl Close should be called when DNSFilter is closed")
}

// TestHashPrefix_Close verifies that the hashprefix.Checker.Close() method
// properly closes the underlying upstream connection.
func TestHashPrefix_Close(t *testing.T) {
	var closeCalled bool
	
	// Create mock upstream that tracks Close calls
	upstream := aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
		return &dns.Msg{}, nil
	})
	upstream.OnClose = func() error {
		closeCalled = true
		return nil
	}

	// Create checker with the mock upstream
	checker := hashprefix.New(&hashprefix.Config{
		Logger:    slogutil.NewDiscardLogger(),
		Upstream:  upstream,
		TXTSuffix: "test.dns",
		CacheTime: 0,
		CacheSize: 0,
	})

	// Verify Close is not called initially
	assert.False(t, closeCalled, "Close should not be called initially")

	// Close the checker
	err := checker.Close()
	require.NoError(t, err)

	// Verify that Close was called on the upstream
	assert.True(t, closeCalled, "Close should be called on the upstream")
}

// TestHashPrefix_Close_NilUpstream verifies that Close handles nil upstream gracefully.
func TestHashPrefix_Close_NilUpstream(t *testing.T) {
	checker := hashprefix.New(&hashprefix.Config{
		Logger:    slogutil.NewDiscardLogger(),
		Upstream:  nil, // nil upstream
		TXTSuffix: "test.dns",
		CacheTime: 0,
		CacheSize: 0,
	})

	// Close should not panic with nil upstream
	err := checker.Close()
	assert.NoError(t, err)
}