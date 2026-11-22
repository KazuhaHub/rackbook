package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sort"
	"sync"
)

// offsetEvery is how many lines lie between two entries of a file's offset index.
const offsetEvery = 512

type offsetMark struct {
	seq, off int64
}

// fileOffsets is a sparse seq -> offset index of one month file: the first line
// and then every offsetEvery-th. It lets Read seek near its cursor instead of
// parsing every newer line of a big file. It lives in memory only, grows with
// the file, and is dropped when the file shrinks or is replaced.
type fileOffsets struct {
	info  os.FileInfo
	size  int64 // the bytes covered: up to the end of the last complete line seen
	lines int
	marks []offsetMark
	bad   bool // seqs are not increasing: the file cannot be seeked in
}

type offsetIndex struct {
	mu    sync.Mutex
	files map[string]*fileOffsets
}

// seekEnd returns the offset to read backward from so that every line with a
// seq below before lies before it: a line start at which all lines have a seq
// of before or more, or the end of the file.
func (o *offsetIndex) seekEnd(name string, f *os.File, before int64) int64 {
	st, err := f.Stat()
	if err != nil {
		return -1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.files == nil {
		o.files = map[string]*fileOffsets{}
	}
	fo := o.files[name]
	if fo == nil || !os.SameFile(fo.info, st) || st.Size() < fo.size {
		fo = &fileOffsets{info: st}
		o.files[name] = fo
	}
	fo.info = st
	if !fo.bad && st.Size() > fo.size {
		fo.extend(f, st.Size())
	}
	if fo.bad {
		return -1
	}
	i := sort.Search(len(fo.marks), func(i int) bool { return fo.marks[i].seq >= before })
	if i == len(fo.marks) {
		return -1
	}
	return fo.marks[i].off
}

// extend reads the complete lines between fo.size and end.
func (fo *fileOffsets) extend(f *os.File, end int64) {
	br := bufio.NewReader(io.NewSectionReader(f, fo.size, end-fo.size))
	off := fo.size
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return // a last line without its newline is not covered yet
		}
		if fo.lines%offsetEvery == 0 {
			var e Event
			if json.Unmarshal(line, &e) != nil || (len(fo.marks) > 0 && e.Seq <= fo.marks[len(fo.marks)-1].seq) {
				fo.bad = true
				return
			}
			fo.marks = append(fo.marks, offsetMark{e.Seq, off})
		}
		fo.lines++
		off += int64(len(line))
		fo.size = off
	}
}
