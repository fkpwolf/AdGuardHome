package filtering

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/hashprefix"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleSafeBrowsingDisable_ClosesConnections verifies that the safebrowsing disable
// handler closes the underlying HTTPS connections.
func TestHandleSafeBrowsingDisable_ClosesConnections(t *testing.T) {
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
		TXTSuffix: "sb.dns.test",
		CacheTime: 0,
		CacheSize: 0,
	})

	// Create config modifier
	confModifier := &aghtest.ConfigModifier{}
	confModifier.OnApply = func(_ context.Context) {
		// No-op for test
	}

	// Create DNSFilter
	dnsFilter, err := New(&Config{
		Logger:              slogutil.NewDiscardLogger(),
		SafeBrowsingChecker: checker,
		SafeBrowsingEnabled: true,
		ProtectionEnabled:   true,
		ConfModifier:        confModifier,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(dnsFilter.Close)

	// Verify Close is not called initially
	assert.False(t, closeCalled, "Close should not be called initially")

	// Create a request to disable safebrowsing
	req := httptest.NewRequest(http.MethodPost, "/control/safebrowsing/disable", nil)
	w := httptest.NewRecorder()

	// Call the disable handler
	dnsFilter.handleSafeBrowsingDisable(w, req)

	// Verify that Close was called on the checker
	assert.True(t, closeCalled, "Close should be called when safebrowsing is disabled")
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestHandleParentalDisable_ClosesConnections verifies that the parental disable
// handler closes the underlying HTTPS connections.
func TestHandleParentalDisable_ClosesConnections(t *testing.T) {
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
		TXTSuffix: "pc.dns.test",
		CacheTime: 0,
		CacheSize: 0,
	})

	// Create config modifier
	confModifier := &aghtest.ConfigModifier{}
	confModifier.OnApply = func(_ context.Context) {
		// No-op for test
	}

	// Create DNSFilter
	dnsFilter, err := New(&Config{
		Logger:                 slogutil.NewDiscardLogger(),
		ParentalControlChecker: checker,
		ParentalEnabled:        true,
		ProtectionEnabled:      true,
		ConfModifier:           confModifier,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(dnsFilter.Close)

	// Verify Close is not called initially
	assert.False(t, closeCalled, "Close should not be called initially")

	// Create a request to disable parental control
	req := httptest.NewRequest(http.MethodPost, "/control/parental/disable", nil)
	w := httptest.NewRecorder()

	// Call the disable handler
	dnsFilter.handleParentalDisable(w, req)

	// Verify that Close was called on the checker
	assert.True(t, closeCalled, "Close should be called when parental control is disabled")
	assert.Equal(t, http.StatusOK, w.Code)
}