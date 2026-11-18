package types

import (
	"fmt"
	"strings"
)

// unifiedDiff renders a unified diff (3 lines of context) between two texts.
// Files are small, so a plain longest-common-subsequence over the lines that
// differ is enough.
func unifiedDiff(name, a, b string) string {
	if a == b {
		return ""
	}
	x, y := splitLines(a), splitLines(b)
	// trim the common head and tail so the table only covers what changed
	head := 0
	for head < len(x) && head < len(y) && x[head] == y[head] {
		head++
	}
	tail := 0
	for tail < len(x)-head && tail < len(y)-head && x[len(x)-1-tail] == y[len(y)-1-tail] {
		tail++
	}
	mx, my := x[head:len(x)-tail], y[head:len(y)-tail]
	ops := lcsOps(mx, my)
	// full edit script with the common parts
	var script []op
	for i := 0; i < head; i++ {
		script = append(script, op{' ', x[i]})
	}
	script = append(script, ops...)
	for i := len(x) - tail; i < len(x); i++ {
		script = append(script, op{' ', x[i]})
	}
	oldName, newName := "a/"+name, "b/"+name
	if a == "" {
		oldName = "/dev/null"
	}
	if b == "" {
		newName = "/dev/null"
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", oldName, newName)
	const ctx = 3
	// find hunks: ranges of the script around changes
	n := len(script)
	i := 0
	oldLine, newLine := 1, 1
	lineAt := make([][2]int, n+1) // old and new line numbers before script[i]
	for k := 0; k < n; k++ {
		lineAt[k] = [2]int{oldLine, newLine}
		switch script[k].kind {
		case ' ':
			oldLine++
			newLine++
		case '-':
			oldLine++
		case '+':
			newLine++
		}
	}
	lineAt[n] = [2]int{oldLine, newLine}
	for i < n {
		if script[i].kind == ' ' {
			i++
			continue
		}
		start := max(0, i-ctx)
		end := i
		for end < n {
			// extend while a change lies within 2*ctx lines
			j := end
			for j < n && script[j].kind != ' ' {
				j++
			}
			end = j
			k := j
			for k < n && script[k].kind == ' ' {
				k++
			}
			if k < n && k-j <= 2*ctx {
				end = k
				continue
			}
			break
		}
		stop := min(n, end+ctx)
		oc, nc := 0, 0
		for k := start; k < stop; k++ {
			switch script[k].kind {
			case ' ':
				oc++
				nc++
			case '-':
				oc++
			case '+':
				nc++
			}
		}
		os, ns := lineAt[start][0], lineAt[start][1]
		if oc == 0 {
			os--
		}
		if nc == 0 {
			ns--
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", os, oc, ns, nc)
		for k := start; k < stop; k++ {
			out.WriteString(string(script[k].kind) + script[k].text + "\n")
		}
		i = stop
	}
	return out.String()
}

type op struct {
	kind rune // ' ', '-', '+'
	text string
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func lcsOps(a, b []string) []op {
	n, m := len(a), len(b)
	if n == 0 || m == 0 || n*m > 4_000_000 {
		// nothing in common to look for, or too large for the table: replace
		out := make([]op, 0, n+m)
		for _, s := range a {
			out = append(out, op{'-', s})
		}
		for _, s := range b {
			out = append(out, op{'+', s})
		}
		return out
	}
	t := make([][]int32, n+1)
	for i := range t {
		t[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	var out []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, op{' ', a[i]})
			i++
			j++
		case t[i+1][j] >= t[i][j+1]:
			out = append(out, op{'-', a[i]})
			i++
		default:
			out = append(out, op{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, op{'-', a[i]})
	}
	for ; j < m; j++ {
		out = append(out, op{'+', b[j]})
	}
	return out
}
