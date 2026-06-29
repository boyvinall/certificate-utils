package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/urfave/cli/v3"
)

var version = "dev"

func main() {
	app := &cli.Command{
		Name:                  "certificate-utils",
		Usage:                 "inspect, convert, and verify TLS certificates (PEM, DER, PFX/PKCS12)",
		EnableShellCompletion: true,
		Version:               version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "level",
				Aliases: []string{"l"},
				Value:   "info",
				Usage:   "log level (debug, info, warn, error)",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			var level slog.Level
			if err := level.UnmarshalText([]byte(cmd.String("level"))); err != nil {
				return ctx, fmt.Errorf("invalid log level %q: %w", cmd.String("level"), err)
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
			return ctx, nil
		},
		Commands: []*cli.Command{
			connectCmd,
			convertCmd,
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return cli.ShowAppHelp(cmd)
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
