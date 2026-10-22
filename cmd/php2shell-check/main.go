package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/yehezkiel1086/php2shell-check/internal/cli"
)

// Build metadata injected at link time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	info := cli.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	return cli.Run(ctx, info, os.Args[1:], os.Stdout, os.Stderr)
}
