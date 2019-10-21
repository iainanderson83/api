package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"github.com/iainanderson83/api/go/api"
)

// This is a reference implementation of an API that we'll
// implement in several other languages.
//
// Most of the advice for Go, especially when starting out,
// is to use the standard libraries + negroni + gorilla so here it is.
func main() {
	sig := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		time.Sleep(time.Second) // let everything start
		fmt.Fprintf(os.Stdout, "%s received\n", <-sig)
		cancel()
	}()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	api.Get("/fib", fib)
	return api.Serve(ctx)
}

func fib(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	n, err := strconv.Atoi(vars["n"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := fastfib(n)

	// This is very obviously not necessary but its good for the comparison
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(buf.Bytes()); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}

func fastfib(n int) int {
	var (
		curr   int
		twoAgo int
		oneAgo = 1
	)
	for i := 2; i <= n; i++ {
		curr = twoAgo + oneAgo
		twoAgo = oneAgo
		oneAgo = curr
	}
	return curr
}
