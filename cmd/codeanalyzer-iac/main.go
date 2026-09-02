package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/cli"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
)

var version = "0.1.0-dev"

type bootstrapRunner struct{}

func (bootstrapRunner) Run(context.Context, options.Options) error {
	return errors.New("analysis pipeline is not wired")
}

func main() {
	if err := cli.New(version, bootstrapRunner{}).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
