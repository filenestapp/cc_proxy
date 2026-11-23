package main

import (
	"fmt"
	"os"
	"sync"
)

// rotatingFile appends to path and keeps keep older files of at most limit bytes (path.1 is the newest). Used for
// --log-file on Windows, where no service manager collects the agent's and sing-box's output.
type rotatingFile struct {
	mu    sync.Mutex
	path  string
	limit int64
	keep  int
	f     *os.File
	size  int64
}

func openRotating(path string, limit int64, keep int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, limit: limit, keep: keep}
	return r, r.open()
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.limit && r.size > 0 {
		r.f.Close()
		for i := r.keep - 1; i >= 1; i-- {
			os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
		}
		os.Rename(r.path, r.path+".1")
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}
