package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/kazuhahub/rackbook/internal/anchor"
	"github.com/kazuhahub/rackbook/internal/audit"
)

// anchorWiring connects the daily audit anchor to the store: AfterPull goes into
// gitstore.Options (it exists before the store does), and Start runs once the store is open.
type anchorWiring struct {
	log    *audit.Log
	logger *slog.Logger
	a      atomic.Pointer[anchor.Anchorer]
}

// AfterPull checks the anchors after a periodic pull: only what was not verified before, and the
// newest, and the commits of the anchor file since the last check.
func (w *anchorWiring) AfterPull() {
	if a := w.a.Load(); a != nil {
		a.Verify(false)
	}
}

// Start checks everything once and, unless the server is read-only, runs the writer loop until
// ctx ends.
func (w *anchorWiring) Start(ctx context.Context, store anchor.Files, readOnly bool) *anchor.Anchorer {
	a := &anchor.Anchorer{Log: w.log, Store: store, Logger: w.logger}
	w.a.Store(a)
	a.Verify(true)
	switch {
	case readOnly:
		if store.Config().AuditAnchorDaily() {
			w.logger.Warn("audit.anchor: daily writes a commit, so --read-only writes no anchors; existing anchors are still checked")
		}
	default:
		go a.Run(ctx)
	}
	return a
}
