// Package ui provides the embedded SimpleAuth admin UI filesystem.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist/*
var files embed.FS

// FS returns the admin UI filesystem, rooted at the dist/ directory.
// Pass this to server.New() when embedding SimpleAuth in your application.
func FS() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic("simpleauth/ui: " + err.Error())
	}
	return sub
}
