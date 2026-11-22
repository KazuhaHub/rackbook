package audit

import (
	"io"
	"log/slog"
)

func slogTo(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
