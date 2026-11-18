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

// Pathological inputs: each must scan in under a second per megabyte.
func pathological() map[string]string {
	rep := func(unit string, n int) string { return strings.Repeat(unit, n/len(unit)+1)[:n] }
	rng := rand.New(rand.NewSource(3))
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%"
	var toks strings.Builder
	for toks.Len() < 1<<20 {
		for i := 0; i < 24; i++ {
			toks.WriteByte(alnum[rng.Intn(len(alnum))])
		}
		toks.WriteByte(' ')
	}
	zh := "今天我们讨论服务器维护计划和备份窗口，请大家准备。密码："
	return map[string]string{
		"password=op:// repeated": rep("password=op://", 1<<20),
		"密码： every 54 bytes":      rep(zh, 1<<20),
		"password= repeated":      rep("password=", 1<<20),
		"?token= repeated":        rep("?token=", 1<<20),
		"random 24-char tokens":   toks.String(),
	}
}

func BenchmarkPathological(b *testing.B) {
	d := Default()
	for name, text := range pathological() {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				d.matches(text)
			}
		})
	}
}

func TestPathologicalInputsStayLinear(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector slows everything several times")
	}
	d := Default()
	for name, text := range pathological() {
		best := time.Hour
		for i := 0; i < 2; i++ {
			start := time.Now()
			d.matches(text)
			if el := time.Since(start); el < best {
				best = el
			}
		}
		// Shared CI runners (windows-arm64 especially) are a few times slower
		// than a laptop; the regressions this guards against (exponential or
		// quadratic scanning) take 100 s or more per megabyte, so 5 s still
		// catches them without failing on slow hardware.
		if best > 5*time.Second {
			t.Errorf("%s: %d bytes took %v", name, len(text), best)
		}
	}
	// the exponential case was 560 bytes of this
	start := time.Now()
	d.matches(strings.Repeat("password=op://", 40))
	if el := time.Since(start); el > time.Second {
		t.Errorf("560 bytes of password=op:// took %v", el)
	}
}
