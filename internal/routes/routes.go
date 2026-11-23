// Package routes is the one thing the packages that mount their own HTTP
// routes (login, oauthserver) need from a mux. The API hands them a recording
// mux, so a test can list every route that is registered.
package routes

import "net/http"

// Mux registers handlers by pattern; *http.ServeMux implements it.
type Mux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

var _ Mux = (*http.ServeMux)(nil)
