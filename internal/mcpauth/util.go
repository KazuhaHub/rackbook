package mcpauth

import (
	"context"
	"encoding/json"
	"net/http"
)

type contextT = context.Context

func writeJSON(w http.ResponseWriter, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
