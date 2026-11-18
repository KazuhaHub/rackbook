// Package web embeds the built console (web/dist).
package web

import "embed"

// FS holds the console build output under "dist". The directory always
// contains at least a .gitkeep so the embed pattern matches before the first
// build; the server shows a "console not built" page when dist/index.html is
// missing.
//
//go:embed all:dist
var FS embed.FS
