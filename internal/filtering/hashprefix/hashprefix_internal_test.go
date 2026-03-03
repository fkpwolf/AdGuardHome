package hashprefix

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cacheTime = 10 * time.Minute
	cacheSize = 10000
)

// testLogger is a logger used in tests.
var testLogger = slogutil.NewDiscardLogger()

func TestChcker_getQuestion(t *testing.T) {
	const suf = "sb.dns.adguard.com."

	// test hostnameToHashes()
	hashes := hostnameToHashes("1.2.3.sub.host.com")
	assert.Len(t, hashes, 3)

	hash := hostnameHash(sha256.Sum256([]byte("3.sub.host.com")))
	hexPref1 := hex.EncodeToString(hash[:prefixLen])
	assert.True(t, slices.Contains(hashes, hash))

	hash = sha256.Sum256([]byte("sub.host.com"))
	hexPref2 := hex.EncodeToString(hash[:prefixLen])
	assert.True(t, slices.Contains(hashes, hash))

	hash = sha256.Sum256([]byte("host.com"))
	hexPref3 := hex.EncodeToString(hash[:prefixLen])
	assert.True(t, slices.Contains(hashes, hash))

	hash = sha256.Sum256([]byte("com"))
	assert.False(t, slices.Contains(hashes, hash))

	c := New(&Config{
		Logger:    testLogger,
		TXTSuffix: suf,
	})

	q := c.getQuestion(hashes)

	assert.Contains(t, q, hexPref1)
	assert.Contains(t, q, hexPref2)
	assert.Contains(t, q, hexPref3)
	assert.True(t, strings.HasSuffix(q, suf))
}

func TestHostnameToHashes(t *testing.T) {
	testCases := []struct {
		name    string
		host    string
		wantLen int
	}{{
		name:    "basic",
		host:    "example.com",
		wantLen: 1,
	}, {
		name:    "sub_basic",
		host:    "www.example.com",
		wantLen: 2,
	}, {
		name:    "private_domain",
		host:    "foo.co.uk",
		wantLen: 1,
	}, {
		name:    "sub_private_domain",
		host:    "bar.foo.co.uk",
		wantLen: 2,
	}, {
		name:    "private_domain_v2",
		host:    "foo.dyndns.org",
		wantLen: 3,
	}, {
		name:    "sub_private_domain_v2",
		host:    "bar.foo.dyndns.org",
		wantLen: 4,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hashes := hostnameToHashes(tc.host)
			assert.Len(t, hashes, tc.wantLen)
		})
	}
}

func TestChecker_storeInCache(t *testing.T) {
	const testTimeout = 1 * time.Second

	c := New(&Config{
		Logger:    testLogger,
		CacheTime: cacheTime,
	})

	conf := cache.Config{}
	c.cache = cache.New(conf)

	// store in cache hashes for "3.sub.host.com" and "host.com"
	//  and empty data for hash-prefix for "sub.host.com"
	hashes := []hostnameHash{}
	hash := hostnameHash(sha256.Sum256([]byte("sub.host.com")))
	hashes = append(hashes, hash)
	var hashesArray []hostnameHash
	hash4 := sha256.Sum256([]byte("3.sub.host.com"))
	hashesArray = append(hashesArray, hash4)
	hash2 := sha256.Sum256([]byte("host.com"))
	hashesArray = append(hashesArray, hash2)
	c.storeInCache(testutil.ContextWithTimeout(t, testTimeout), hashes, hashesArray)

	// match "3.sub.host.com" or "host.com" from cache
	hashes = []hostnameHash{}
	hash = sha256.Sum256([]byte("3.sub.host.com"))
	hashes = append(hashes, hash)
	hash = sha256.Sum256([]byte("sub.host.com"))
	hashes = append(hashes, hash)
	hash = sha256.Sum256([]byte("host.com"))
	hashes = append(hashes, hash)
	found, blocked, _ := c.findInCache(hashes)
	assert.True(t, found)
	assert.True(t, blocked)

	// match "sub.host.com" from cache
	hashes = []hostnameHash{}
	hash = sha256.Sum256([]byte("sub.host.com"))
	hashes = append(hashes, hash)
	found, blocked, _ = c.findInCache(hashes)
	assert.True(t, found)
	assert.False(t, blocked)

	// Match "sub.host.com" from cache.  Another hash for "host.example" is not
	// in the cache, so get data for it from the server.
	hashes = []hostnameHash{}
	hash = sha256.Sum256([]byte("sub.host.com"))
	hashes = append(hashes, hash)
	hash = sha256.Sum256([]byte("host.example"))
	hashes = append(hashes, hash)
	found, _, hashesToRequest := c.findInCache(hashes)
	assert.False(t, found)

	hash = sha256.Sum256([]byte("sub.host.com"))
	ok := slices.Contains(hashesToRequest, hash)
	assert.False(t, ok)

	hash = sha256.Sum256([]byte("host.example"))
	ok = slices.Contains(hashesToRequest, hash)
	assert.True(t, ok)

	c = New(&Config{
		Logger:    testLogger,
		CacheTime: cacheTime,
	})

	c.cache = cache.New(cache.Config{})

	hashes = []hostnameHash{}
	hash = sha256.Sum256([]byte("sub.host.com"))
	hashes = append(hashes, hash)

	c.cache.Set(hash[:prefixLen], make([]byte, expirySize+hashSize))
	found, _, _ = c.findInCache(hashes)
	assert.False(t, found)
}

func TestChecker_Check(t *testing.T) {
	const hostname = "example.org"

	testCases := []struct {
		name      string
		wantBlock bool
	}{{
		name:      "sb_no_block",
		wantBlock: false,
	}, {
		name:      "sb_block",
		wantBlock: true,
	}, {
		name:      "pc_no_block",
		wantBlock: false,
	}, {
		name:      "pc_block",
		wantBlock: true,
	}}

	for _, tc := range testCases {
		c := New(&Config{
			Logger:    testLogger,
			CacheTime: cacheTime,
			CacheSize: cacheSize,
		})

		// Prepare the upstream.
		ups := aghtest.NewBlockUpstream(hostname, tc.wantBlock)

		var numReq int
		onExchange := ups.OnExchange
		ups.OnExchange = func(req *dns.Msg) (resp *dns.Msg, err error) {
			numReq++

			return onExchange(req)
		}

		c.upstream = ups

		t.Run(tc.name, func(t *testing.T) {
			// Firstly, check the request blocking.
			hits := 0
			res := false
			res, err := c.Check(hostname)
			require.NoError(t, err)

			if tc.wantBlock {
				assert.True(t, res)
				hits++
			} else {
				require.False(t, res)
			}

			// Check the cache state, check the response is now cached.
			assert.Equal(t, 1, c.cache.Stats().Count)
			assert.Equal(t, hits, c.cache.Stats().Hit)

			// There was one request to an upstream.
			assert.Equal(t, 1, numReq)

			// Now make the same request to check the cache was used.
			res, err = c.Check(hostname)
			require.NoError(t, err)

			if tc.wantBlock {
				assert.True(t, res)
			} else {
				require.False(t, res)
			}

			// Check the cache state, it should've been used.
			assert.Equal(t, 1, c.cache.Stats().Count)
			assert.Equal(t, hits+1, c.cache.Stats().Hit)

			// Check that there were no additional requests.
			assert.Equal(t, 1, numReq)
		})
	}
}

// TestChecker_Check_SamePrefixConcurrent verifies that two goroutines querying
// different hostnames that share the same 2-byte SHA256 prefix each receive an
// independent, correct result even when they share a single upstream request
// through singleflight.
//
// "act.org" and "ahy.org" both produce SHA256 hashes starting with 0x58e3,
// so they generate the same DNS question string and can coalesce in singleflight.
// The upstream returns only the hash of the blocked hostname; the innocent
// hostname must NOT be reported as blocked.
func TestChecker_Check_SamePrefixConcurrent(t *testing.T) {
	const (
		blockedHost  = "act.org"
		innocentHost = "ahy.org"
	)

	blockedHash := sha256.Sum256([]byte(blockedHost))
	blockedHashStr := hex.EncodeToString(blockedHash[:])

	// ready is closed when the upstream receives its first request,
	// confirming that goroutine 1 is blocked inside sf.Do.
	ready := make(chan struct{})
	var readyOnce sync.Once

	// gate is closed to release the upstream response.
	gate := make(chan struct{})

	ups := aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
		readyOnce.Do(func() { close(ready) })
		<-gate

		resp = new(dns.Msg).SetReply(req)
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Txt: []string{blockedHashStr},
		}}

		return resp, nil
	})

	c := New(&Config{
		Logger:    testLogger,
		CacheTime: cacheTime,
		CacheSize: cacheSize,
	})
	c.upstream = ups

	var (
		blockedResult, innocentResult bool
		blockedErr, innocentErr       error
		wg                            sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		blockedResult, blockedErr = c.Check(blockedHost)
	}()

	// Wait until goroutine 1 is confirmed inside the upstream call (and
	// therefore inside sf.Do), so the gate holds it there.
	<-ready

	// Goroutine 1 is now blocked; start goroutine 2 and let it enter sf.Do.
	wg.Add(1)
	go func() {
		defer wg.Done()
		innocentResult, innocentErr = c.Check(innocentHost)
	}()

	// Give goroutine 2 time to enter sf.Do before releasing goroutine 1.
	time.Sleep(10 * time.Millisecond)
	close(gate)

	wg.Wait()

	require.NoError(t, blockedErr)
	require.NoError(t, innocentErr)
	assert.True(t, blockedResult, "blocked host must be blocked")
	assert.False(t, innocentResult, "innocent host with same prefix must not be blocked")
}
