package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

var (
	e error
	r = mux.NewRouter().StrictSlash(true)
)

// Get registers a handler for a GET request.
func Get(path string, handler http.HandlerFunc) {
	if e != nil {
		return
	}
	if err := r.HandleFunc(path, handler).Methods(http.MethodGet, http.MethodOptions).GetError(); err != nil {
		e = err
	}
}

// Post registers a handler for a POST request.
func Post(path string, handler http.HandlerFunc) {
	if e != nil {
		return
	}
	if err := r.HandleFunc(path, handler).Methods(http.MethodPost, http.MethodOptions).GetError(); err != nil {
		e = err
	}
}
