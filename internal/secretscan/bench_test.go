package secretscan

import (
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"time"
)

// mixedText is about n bytes of ordinary-looking ledger prose: words, URLs,
// hex digests, base64, CJK and the odd keyword, with no secret in it.
func mixedText(n int) string {
	words := []string{"nginx", "reverse", "proxy", "backup", "token", "service", "password", "policy", "rotate", "every", "90", "days",
		"主站", "备份", "密码策略", "https://grafana.example.com/d/abcdef/overview?orgId=1", "2001:db8::1", "100.64.0.0/10", "key", "secret", "storage",
		"0123456789abcdef0123456789abcdef", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", "ssh://git@github.com/org/repo.git", "api", "Bearer", "pass", "是", "：", "=", ":"}
	rng := rand.New(rand.NewSource(1))
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words[rng.Intn(len(words))])
		b.WriteByte(' ')
	}
	return b.String()
}

func BenchmarkScanMegabyte(b *testing.B) {
	text := mixedText(1 << 20)
	d := Default()
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.matches(text)
	}
}

func TestScanMegabyteIsFastAndLight(t *testing.T) {
	text := mixedText(1 << 20)
	d := Default()
	best := time.Hour
	var alloc uint64
	for i := 0; i < 3; i++ { // best of three: other packages' tests share the CPU
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		d.matches(text)
		if el := time.Since(start); el < best {
			best = el
		}
		runtime.ReadMemStats(&after)
		alloc = after.TotalAlloc - before.TotalAlloc
	}
	if best > 300*time.Millisecond && !raceEnabled { // the race detector slows everything several times
		t.Errorf("1 MB took %v", best)
	}
	if alloc > 10<<20 {
		t.Errorf("1 MB allocated %d bytes", alloc)
	}
}
