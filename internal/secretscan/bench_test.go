package secretscan

import (
	"fmt"
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

// TestScanMegabyteIsFastAndLight: ordinary text of 1 MB scans within a loose
// time bound and a bounded allocation.
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
	// About 0.1 s on a laptop (see BenchmarkScanMegabyte). The test bound is
	// generous so loaded or slow CI runners don't fail it; scaling is checked
	// by TestPathologicalInputsStayLinear. The allocation bound guards memory.
	if best > 3*time.Second && !raceEnabled { // the race detector slows everything several times
		t.Errorf("1 MB took %v", best)
	}
	if alloc > 10<<20 {
		t.Errorf("1 MB allocated %d bytes", alloc)
	}
}

// pathological returns n-byte inputs that each target one way a scan could go
// super-linear: backtracking on repeated keywords, a long unterminated value, a
// reference prefix, a flood of tokens, and many keyword assignments next to many
// entropy tokens (the case that made hit de-duplication quadratic).
func pathological(n int) map[string]string {
	rep := func(unit string, n int) string { return strings.Repeat(unit, n/len(unit)+1)[:n] }
	rng := rand.New(rand.NewSource(3))
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%"
	const plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var toks, pairs strings.Builder
	for toks.Len() < n {
		for i := 0; i < 24; i++ {
			toks.WriteByte(alnum[rng.Intn(len(alnum))])
		}
		toks.WriteByte(' ')
	}
	for i := 0; pairs.Len() < n; i++ {
		fmt.Fprintf(&pairs, "pwd=v%07d ", i)
		for j := 0; j < 24; j++ {
			pairs.WriteByte(plain[rng.Intn(len(plain))])
		}
		pairs.WriteByte(' ')
	}
	zh := "今天我们讨论服务器维护计划和备份窗口，请大家准备。密码："
	return map[string]string{
		"password=op:// repeated": rep("password=op://", n),
		"密码： every 54 bytes":      rep(zh, n),
		"password= repeated":      rep("password=", n),
		"?token= repeated":        rep("?token=", n),
		"random 24-char tokens":   toks.String()[:n],
		"assignments and tokens":  pairs.String()[:n],
	}
}

func BenchmarkPathological(b *testing.B) {
	d := Default()
	for name, text := range pathological(1 << 20) {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				d.matches(text)
			}
		})
	}
}

// TestPathologicalInputsStayLinear guards against super-linear scanning (a
// quadratic loop, backtracking). A wall-clock bound cannot tell a slow linear
// scan from a quadratic one, so it compares two sizes: the best of five scans at
// 4n bytes must take at most 10 times as long as at n bytes (linear is about 4,
// quadratic about 16). The two sizes are timed alternately so that load on the
// machine hits both alike, and a generator is retried up to three times: it
// fails only if every attempt is over.
func TestPathologicalInputsStayLinear(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector slows everything several times")
	}
	const small, large = 512 << 10, 2 << 20
	d := Default()
	smalls, larges := pathological(small), pathological(large)
	for name := range smalls {
		var ts, tl time.Duration
		ok := false
		for attempt := 0; attempt < 3 && !ok; attempt++ {
			ts, tl = time.Hour, time.Hour
			for i := 0; i < 5; i++ {
				for _, m := range []struct {
					text string
					best *time.Duration
				}{{smalls[name], &ts}, {larges[name], &tl}} {
					start := time.Now()
					d.matches(m.text)
					if el := time.Since(start); el < *m.best {
						*m.best = el
					}
				}
			}
			t.Logf("%s: %v at %d bytes, %v at %d bytes (x%.1f)", name, ts, small, tl, large, float64(tl)/float64(ts))
			ok = tl <= 20*time.Second && tl <= 10*ts
		}
		if !ok {
			t.Errorf("%s: %v at %d bytes but %v at %d bytes: not linear", name, ts, small, tl, large)
		}
	}
}

// TestPasswordOpRepeatedIsNotExponential guards against exponential
// backtracking: this input was 560 bytes of the "password=op://" case.
func TestPasswordOpRepeatedIsNotExponential(t *testing.T) {
	start := time.Now()
	Default().matches(strings.Repeat("password=op://", 40))
	if el := time.Since(start); el > time.Second {
		t.Errorf("560 bytes of password=op:// took %v", el)
	}
}
