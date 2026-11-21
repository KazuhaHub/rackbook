package ansiblerepo

import (
	"fmt"
	"regexp"
	"strings"
)

// FileDiff is the change of one file, as a unified diff.
type FileDiff struct {
	Path string `json:"path"`
	// Status is "added", "modified" or "removed".
	Status string `json:"status"`
	Diff   string `json:"diff"`
}

const diffContext = 3

// maxDiffCells bounds the work of the line diff; a larger pair of files is
// shown as a full replacement.
const maxDiffCells = 4_000_000

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.Split(s, "\n")
}

// unifiedDiff compares two versions of a file. Lines that look like secrets are
// shown as "(hidden)": a preview must not copy a value out of the repository.
func unifiedDiff(path string, before, after []byte) FileDiff {
	d := FileDiff{Path: path, Status: "modified"}
	switch {
	case before == nil && after != nil:
		d.Status = "added"
	case before != nil && after == nil:
		d.Status = "removed"
	}
	a, b := splitLines(before), splitLines(after)
	ops := diffOps(a, b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", pathOrNull(before, "a/"+path), pathOrNull(after, "b/"+path))
	// group ops into hunks with context
	type span struct{ lo, hi int } // indexes into ops
	var hunks []span
	for i, o := range ops {
		if o.kind == ' ' {
			continue
		}
		lo, hi := max(0, i-diffContext), min(len(ops), i+1+diffContext)
		if n := len(hunks); n > 0 && lo <= hunks[n-1].hi {
			hunks[n-1].hi = hi
		} else {
			hunks = append(hunks, span{lo, hi})
		}
	}
	for _, h := range hunks {
		var oldN, newN, oldStart, newStart int
		oldStart, newStart = 1, 1
		for _, o := range ops[:h.lo] {
			if o.kind != '+' {
				oldStart++
			}
			if o.kind != '-' {
				newStart++
			}
		}
		for _, o := range ops[h.lo:h.hi] {
			if o.kind != '+' {
				oldN++
			}
			if o.kind != '-' {
				newN++
			}
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", oldStart, oldN, newStart, newN)
		for _, o := range ops[h.lo:h.hi] {
			sb.WriteByte(o.kind)
			sb.WriteString(redactLine(o.line))
			sb.WriteByte('\n')
		}
	}
	d.Diff = sb.String()
	return d
}

func pathOrNull(b []byte, p string) string {
	if b == nil {
		return "/dev/null"
	}
	return p
}

var keyedLineRe = regexp.MustCompile(`^(\s*(?:-\s+)?[^\s#:][^:#]*:\s+)(\S.*)$`)

// redactLine hides what looks like a secret in one line of YAML.
func redactLine(l string) string {
	t := strings.TrimSpace(l)
	if strings.HasPrefix(t, "#") {
		if commentSecret(t) {
			return leadingSpace(l) + "# " + Hidden
		}
		return l
	}
	if m := keyedLineRe.FindStringSubmatch(l); m != nil && secretKeyRe.MatchString(m[1]) {
		return m[1] + Hidden
	}
	if secretValueRe.MatchString(l) {
		return leadingSpace(l) + Hidden
	}
	return l
}

func leadingSpace(l string) string { return l[:len(l)-len(strings.TrimLeft(l, " \t"))] }

type diffOp struct {
	kind byte // ' ', '-', '+'
	line string
}

// diffOps is the shortest edit script between a and b (common prefix and
// suffix trimmed, longest common subsequence in between).
func diffOps(a, b []string) []diffOp {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	var ops []diffOp
	for _, l := range a[:pre] {
		ops = append(ops, diffOp{' ', l})
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	if len(ma)*len(mb) > maxDiffCells {
		for _, l := range ma {
			ops = append(ops, diffOp{'-', l})
		}
		for _, l := range mb {
			ops = append(ops, diffOp{'+', l})
		}
	} else {
		ops = append(ops, lcsOps(ma, mb)...)
	}
	for _, l := range a[len(a)-suf:] {
		ops = append(ops, diffOp{' ', l})
	}
	return ops
}

func lcsOps(a, b []string) []diffOp {
	n, m := len(a), len(b)
	w := m + 1
	t := make([]int32, (n+1)*w)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				t[i*w+j] = t[(i+1)*w+j+1] + 1
			} else {
				t[i*w+j] = max(t[(i+1)*w+j], t[i*w+j+1])
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case t[(i+1)*w+j] >= t[i*w+j+1]:
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', b[j]})
	}
	return ops
}
