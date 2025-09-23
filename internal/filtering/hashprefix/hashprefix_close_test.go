package hashprefix

import (
	"log/slog"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChecker_Close(t *testing.T) {
	closed := false
	ups := &aghtest.UpstreamMock{
		OnAddress: func() (addr string) { return "upstream.example" },
		OnExchange: func(_ *dns.Msg) (resp *dns.Msg, err error) {
			return nil, nil
		},
		OnClose: func() (err error) {
			closed = true
			return nil
		},
	}

	c := New(&Config{
		Logger:    slog.Default(),
		Upstream:  ups,
		TXTSuffix: "test.example",
		CacheTime: 10 * time.Second,
		CacheSize: 100,
	})

	// Ensure the checker is not closed initially
	assert.False(t, closed)

	// Close the checker
	err := c.Close()
	require.NoError(t, err)

	// Ensure the upstream was closed
	assert.True(t, closed)
}