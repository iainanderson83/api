package runner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Run executes the specified function with a cancelable context.
func Run(fn func(context.Context) error) {
	sig := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		time.Sleep(time.Second) // let everything start
		fmt.Fprintf(os.Stdout, "%s received\n", <-sig)
		cancel()
	}()

	if err := fn(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
