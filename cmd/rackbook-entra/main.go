// Command rackbook-entra keeps one Rackbook record per Microsoft Entra
// application or service principal credential, so their expiry dates show up
// in Rackbook. It talks to Rackbook only through its public HTTP API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kazuhahub/rackbook/modules/rbclient"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("rackbook-entra", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/rackbook/entra.yml", "path of the config file")
	once := fs.Bool("once", false, "run one sync and exit")
	dry := fs.Bool("dry-run", false, "print the planned changes and write nothing")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("rackbook-entra", version)
		return 0
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		return 2
	}
	a, err := newApp(cfg, log)
	if err != nil {
		log.Error("setup", "err", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version, "once", *once, "dry_run", *dry)
	for {
		res, err := a.syncOnce(ctx, *dry)
		if ctx.Err() != nil {
			log.Info("stopping")
			return 0
		}
		failed := err != nil || res.Failed > 0
		if err != nil {
			log.Error("sync failed", "err", err)
		}
		if *once {
			if failed {
				return 1
			}
			return 0
		}
		select {
		case <-ctx.Done():
			log.Info("stopping")
			return 0
		case <-time.After(cfg.Interval):
		}
	}
}

func newApp(cfg *Config, log *slog.Logger) (*app, error) {
	key, cert, err := loadKeyPair(rbclient.SecretPath(cfg.Entra.CertificateFile))
	if err != nil {
		return nil, err
	}
	token, err := rbclient.ReadSecret(cfg.Rackbook.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("rackbook token: %w", err)
	}
	rb, err := rbclient.New(cfg.Rackbook.URL, token)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: 60 * time.Second}
	ts := newTokenSource(cfg.Entra, key, cert, hc)
	return &app{
		cfg:   cfg,
		graph: newGraphClient(cfg.Entra.GraphURL, ts, hc),
		rb:    rb,
		out:   os.Stdout,
		now:   time.Now,
		log:   log,
	}, nil
}
