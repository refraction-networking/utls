// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// update three-way merges the committed mirror onto pristine(newV).
//
// Safety rules:
//   - It refuses to start while a previous update is unresolved.
//   - It aborts BEFORE touching the tree if pristine(newV) imports a
//     std-internal package that upstream/imports.txt does not map.
//   - On conflicts (content, modify/delete, add/add) or when an upstream
//     package that a hand-written shim replaces has changed, it records
//     upstream/UPDATE_STATE and leaves upstream/VERSION unchanged, so neither
//     `check` nor CI can mistake the tree for a completed update. `finish`
//     completes the update once the markers are gone and shims are reviewed.
func (r *repo) update(newV string, w io.Writer) error {
	if _, ok := readOpt(r.up(stateFile)); ok {
		return errors.New("an update is already in progress; resolve it and run 'finish'")
	}
	oldV, err := r.version()
	if err != nil {
		return err
	}
	if oldV == newV {
		return fmt.Errorf("already at %s", newV)
	}
	tmp, err := os.MkdirTemp("", "utls-sync-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	oldDir, newDir := filepath.Join(tmp, "old"), filepath.Join(tmp, "new")
	fmt.Fprintf(w, "pristine %s ...\n", oldV)
	oldFiles, err := r.pristine(oldV, oldDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "pristine %s ...\n", newV)
	newFiles, err := r.pristine(newV, newDir)
	if err != nil {
		return err
	}
	// Report std-internal imports that are NEW in this release (ones already
	// present in pristine(old) are handled by existing [uTLS] hunks).
	oldBad, err := unmappedImports(oldDir, oldFiles)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, b := range oldBad {
		_, p, _ := strings.Cut(b, ": ")
		known[p] = true
	}
	allBad, err := unmappedImports(newDir, newFiles)
	if err != nil {
		return err
	}
	var bad []string
	for _, b := range allBad {
		if _, p, _ := strings.Cut(b, ": "); !known[p] {
			bad = append(bad, b)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("pristine(%s) imports std-internal packages with no mapping in upstream/imports.txt (tree untouched):\n  %s\nadd a mapping or a shim (internal/README.md), then re-run update",
			newV, strings.Join(bad, "\n  "))
	}

	inOld, inNew := set(oldFiles), set(newFiles)
	local := func(f string) string { return filepath.Join(r.root, filepath.FromSlash(f)) }
	var conflicts, log []string
	added := map[string]bool{}
	for _, f := range newFiles {
		if !inOld[f] {
			added[f] = true
		}
	}

	// Renames: a file deleted upstream whose content mostly reappears in an
	// added file. Carry local [uTLS] hunks across by merging onto the new name.
	renamedTo := map[string]string{}
	for _, f := range oldFiles {
		if inNew[f] {
			continue
		}
		ob, _ := os.ReadFile(filepath.Join(oldDir, filepath.FromSlash(f)))
		best, bestScore := "", 0.0
		for g := range added {
			if filepath.Dir(g) != filepath.Dir(f) {
				continue
			}
			nb, _ := os.ReadFile(filepath.Join(newDir, filepath.FromSlash(g)))
			if s := similarity(ob, nb); s > bestScore {
				best, bestScore = g, s
			}
		}
		if bestScore >= 0.6 {
			renamedTo[f] = best
			delete(added, best)
		}
	}

	for _, f := range unionSorted(oldFiles, newFiles) {
		o := filepath.Join(oldDir, filepath.FromSlash(f))
		n := filepath.Join(newDir, filepath.FromSlash(f))
		l := local(f)
		_, lok := readOpt(l)
		switch {
		case inOld[f] && !inNew[f]: // deleted or renamed upstream
			if !lok {
				continue
			}
			lb, _ := os.ReadFile(l)
			ob, _ := os.ReadFile(o)
			if g, ok := renamedTo[f]; ok {
				nb := filepath.Join(newDir, filepath.FromSlash(g))
				if bytes.Equal(lb, ob) {
					copyFile(nb, local(g))
					log = append(log, fmt.Sprintf("renamed  %s -> %s", f, g))
				} else {
					if err := copyFile(l, local(g)); err != nil {
						return err
					}
					clean, err := merge3(local(g), o, nb, oldV, newV)
					if err != nil {
						return err
					}
					if clean {
						log = append(log, fmt.Sprintf("renamed  %s -> %s (merged [uTLS] hunks)", f, g))
					} else {
						conflicts = append(conflicts, fmt.Sprintf("content (rename %s -> %s): %s", f, g, g))
					}
				}
				os.Remove(l)
				continue
			}
			if bytes.Equal(lb, ob) {
				os.Remove(l)
				log = append(log, "removed  "+f)
			} else {
				conflicts = append(conflicts, "modify/delete: "+f+" was deleted upstream but carries [uTLS] hunks; move them to a u_*.go file and delete it")
			}
		case !inOld[f] && inNew[f]:
			if !added[f] {
				continue // handled as a rename target
			}
			if lok {
				conflicts = append(conflicts, "add/add: "+f+" exists locally and was added upstream")
				continue
			}
			if err := copyFile(n, l); err != nil {
				return err
			}
			log = append(log, "added    "+f)
		case inOld[f] && inNew[f]:
			ob, _ := os.ReadFile(o)
			nb, _ := os.ReadFile(n)
			if bytes.Equal(ob, nb) {
				continue
			}
			if !lok {
				conflicts = append(conflicts, "modify/delete: "+f+" changed upstream but was deleted locally")
				continue
			}
			clean, err := merge3(l, o, n, oldV, newV)
			if err != nil {
				return err
			}
			if clean {
				log = append(log, "merged   "+f)
			} else {
				conflicts = append(conflicts, "content: "+f)
			}
		}
	}
	for _, l := range log {
		fmt.Fprintln(w, l)
	}

	// Shims: compare the upstream sources they replace.
	var shimChanged []string
	if ls, err := r.configLines("shims-sources.txt"); err == nil {
		og, _ := r.goroot(oldV)
		ng, _ := r.goroot(newV)
		for _, f := range ls {
			ho, err1 := hashGoDir(filepath.Join(og, "src", filepath.FromSlash(f[1])))
			hn, err2 := hashGoDir(filepath.Join(ng, "src", filepath.FromSlash(f[1])))
			if err1 != nil || err2 != nil || ho != hn {
				shimChanged = append(shimChanged, fmt.Sprintf("%s (upstream %s)", f[0], f[1]))
			}
		}
	}

	if len(conflicts) > 0 || len(shimChanged) > 0 {
		var st strings.Builder
		fmt.Fprintf(&st, "target %s\nfrom %s\n", newV, oldV)
		for _, c := range conflicts {
			fmt.Fprintf(&st, "conflict %s\n", c)
		}
		for _, s := range shimChanged {
			fmt.Fprintf(&st, "shim-review %s\n", s)
		}
		if err := os.WriteFile(r.up(stateFile), []byte(st.String()), 0o644); err != nil {
			return err
		}
		return fmt.Errorf("update %s -> %s is INCOMPLETE: %d conflict(s), %d shim(s) to review; VERSION left at %s.\n%s"+
			"Resolve, review shims against upstream, then run 'upstream/sync.sh finish'",
			oldV, newV, len(conflicts), len(shimChanged), oldV, st.String())
	}
	if err := os.WriteFile(r.up("VERSION"), []byte(newV+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nupstream %s -> %s merged cleanly.\nNext: go build ./... && go test ./..., then 'upstream/sync.sh diff > upstream/utls.patch' and 'upstream/sync.sh shims > upstream/shims.txt'.\n", oldV, newV)
	return nil
}

// finish completes an update recorded in UPDATE_STATE.
func (r *repo) finish(w io.Writer) error {
	b, ok := readOpt(r.up(stateFile))
	if !ok {
		return errors.New("no update in progress")
	}
	var target string
	for _, l := range strings.Split(string(b), "\n") {
		if t, ok := strings.CutPrefix(l, "target "); ok {
			target = strings.TrimSpace(t)
		}
	}
	if target == "" {
		return errors.New("UPDATE_STATE has no target")
	}
	files, err := r.mirroredFiles(r.root)
	if err != nil {
		return err
	}
	for _, f := range files {
		fb, _ := os.ReadFile(filepath.Join(r.root, filepath.FromSlash(f)))
		if hasConflictMarkers(fb) {
			return fmt.Errorf("%s still contains conflict markers", f)
		}
	}
	if err := os.WriteFile(r.up("VERSION"), []byte(target+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Remove(r.up(stateFile)); err != nil {
		return err
	}
	fmt.Fprintf(w, "update to %s finished. Now: go build ./... && go test ./..., regenerate utls.patch and shims.txt, run check.\n", target)
	return nil
}

// merge3 runs `git merge-file` on local (in place) with base and other.
func merge3(local, base, other, baseLabel, otherLabel string) (clean bool, err error) {
	cmd := exec.Command("git", "merge-file", "-L", "uTLS", "-L", baseLabel, "-L", otherLabel, local, base, other)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() > 0 && ee.ExitCode() < 128 {
		return false, nil // exit code = number of conflicts
	}
	return false, fmt.Errorf("git merge-file %s: %v: %s", local, err, stderr.String())
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func unionSorted(a, b []string) []string {
	m := set(a)
	for _, x := range b {
		m[x] = true
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// similarity is the fraction of lines shared (multiset Dice coefficient).
func similarity(a, b []byte) float64 {
	la, lb := splitLines(a), splitLines(b)
	if len(la)+len(lb) == 0 {
		return 1
	}
	count := map[string]int{}
	for _, l := range la {
		count[l]++
	}
	common := 0
	for _, l := range lb {
		if count[l] > 0 {
			count[l]--
			common++
		}
	}
	return 2 * float64(common) / float64(len(la)+len(lb))
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// unifiedDiff returns a unified diff (3 lines of context) in the classic
// `diff -u` format, or nil if a and b are equal. It uses Myers' algorithm, so
// output is deterministic across platforms (no dependency on the host diff).
func unifiedDiff(aName, bName string, a, b []byte) []byte {
	if bytes.Equal(a, b) {
		return nil
	}
	al, bl := splitLines(a), splitLines(b)
	ops := myers(al, bl)
	const ctx = 3
	var out bytes.Buffer
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", aName, bName)
	// Group ops into hunks.
	type op struct {
		kind byte // ' ', '-', '+'
		text string
	}
	var all []op
	for _, o := range ops {
		all = append(all, op{o.kind, o.text})
	}
	i := 0
	for i < len(all) {
		// find next change
		for i < len(all) && all[i].kind == ' ' {
			i++
		}
		if i >= len(all) {
			break
		}
		start := max(0, i-ctx)
		end := i
		for end < len(all) {
			if all[end].kind != ' ' {
				end++
				continue
			}
			// count run of equal lines
			j := end
			for j < len(all) && all[j].kind == ' ' {
				j++
			}
			if j == len(all) || j-end > 2*ctx {
				end = min(len(all), end+ctx)
				break
			}
			end = j
		}
		// line numbers
		aStart, bStart := 1, 1
		for k := 0; k < start; k++ {
			if all[k].kind != '+' {
				aStart++
			}
			if all[k].kind != '-' {
				bStart++
			}
		}
		aCount, bCount := 0, 0
		for k := start; k < end; k++ {
			if all[k].kind != '+' {
				aCount++
			}
			if all[k].kind != '-' {
				bCount++
			}
		}
		fmt.Fprintf(&out, "@@ -%s +%s @@\n", rangeStr(aStart, aCount), rangeStr(bStart, bCount))
		for k := start; k < end; k++ {
			out.WriteByte(all[k].kind)
			t := all[k].text
			if strings.HasSuffix(t, "\n") {
				out.WriteString(t)
			} else {
				out.WriteString(t + "\n\\ No newline at end of file\n")
			}
		}
		i = end
	}
	return out.Bytes()
}

func rangeStr(start, count int) string {
	switch count {
	case 0:
		return fmt.Sprintf("%d,0", start-1)
	case 1:
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d,%d", start, count)
}

type diffOp struct {
	kind byte
	text string
}

// myers computes a shortest edit script between a and b.
func myers(a, b []string) []diffOp {
	n, m := len(a), len(b)
	maxD := n + m
	off := maxD
	v := make([]int, 2*maxD+2)
	var trace [][]int
	for d := 0; d <= maxD; d++ {
		vc := make([]int, len(v))
		copy(vc, v)
		trace = append(trace, vc)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				return backtrack(trace, a, b, off, d, v)
			}
		}
	}
	return nil
}

func backtrack(trace [][]int, a, b []string, off, d int, _ []int) []diffOp {
	x, y := len(a), len(b)
	var rev []diffOp
	for dd := d; dd > 0; dd-- {
		vp := trace[dd] // state after round dd-1
		k := x - y
		var prevK int
		if k == -dd || (k != dd && vp[off+k-1] < vp[off+k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := vp[off+prevK]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			rev = append(rev, diffOp{' ', a[x-1]})
			x--
			y--
		}
		if x == prevX {
			rev = append(rev, diffOp{'+', b[y-1]})
			y--
		} else {
			rev = append(rev, diffOp{'-', a[x-1]})
			x--
		}
	}
	for x > 0 && y > 0 {
		rev = append(rev, diffOp{' ', a[x-1]})
		x--
		y--
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}
