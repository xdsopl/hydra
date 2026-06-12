/*
Simple webserver

Copyright 2024 Ahmet Inan <xdsopl@gmail.com>
*/

package main

import (
	"os"
	"strings"
	"strconv"
	"net/http"
)

func toHTTPError(err error) (msg string, httpStatus int) {
	if os.IsNotExist(err) {
		return "404 page not found", http.StatusNotFound
	}
	if os.IsPermission(err) {
		return "403 Forbidden", http.StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", http.StatusInternalServerError
}

type wasmHandler struct {
	root http.FileSystem
	fsrv http.Handler
}

func WebAssembly(root http.FileSystem) http.Handler {
	return &wasmHandler{root, http.FileServer(root)}
}

func (f *wasmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	if strings.HasSuffix(upath, ".wasm") && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gzip := upath + ".gz"
		file, err := f.root.Open(gzip)
		if err == nil {
			defer file.Close()
			d, err := file.Stat()
			if err != nil {
				msg, code := toHTTPError(err)
				http.Error(w, msg, code)
				return
			}
			if d.IsDir() {
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/wasm")
			w.Header().Set("Content-Length", strconv.FormatInt(d.Size(), 10))
			http.ServeContent(w, r, upath, d.ModTime(), file)
			return
		}
	}
	f.fsrv.ServeHTTP(w, r)
}

func main() {
	http.ListenAndServe(":8080", WebAssembly(http.Dir("assets")))
}

