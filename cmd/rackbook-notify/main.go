// Command rackbook-notify sends a digest of records that are about to expire.
// It reads /api/expiring through the public API and remembers which reminder
// thresholds have fired in a state file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kazuhahub/rackbook/modules/rbclient"
)

var version = "dev"

type notifier struct {
	cfg       *Config
	client    *rbclient.Client
	statePath string
	dryRun    bool
	out       io.Writer
	log       *slog.Logger
}

func newNotifier(cfg *Config, dryRun bool, out io.Writer, log *slog.Logger) (*notifier, error) {
	token, err := rbclient.ReadSecret(cfg.Rackbook.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read rackbook token: %w", err)
	}
	client, err := rbclient.New(cfg.Rackbook.URL, token)
	if err != nil {
		return nil, err
	}
	return &notifier{cfg: cfg, client: client, statePath: resolveStatePath(cfg.StateFile), dryRun: dryRun, out: out, log: log}, nil
}

func (n *notifier) run(ctx context.Context) error {
	state, err := loadState(n.statePath)
	if err != nil {
		return err
	}
	res, err := n.client.Expiring(ctx, n.cfg.Thresholds[0], n.cfg.Collections, false)
	if err != nil {
		return fmt.Errorf("fetch expiring: %w", err)
	}
	due, next := plan(state, res.Items, n.cfg.Thresholds)
	if len(due) == 0 {
		n.log.Info("no reminders due", "listed", len(res.Items))
		if n.dryRun {
			return nil
		}
		return saveState(n.statePath, next)
	}
	digest := buildDigest(n.cfg.Language, n.cfg.Rackbook.URL, due)
	text := digest.Subject + "\n\n" + digest.Body
	if n.dryRun {
		fmt.Fprintf(n.out, "Subject: %s\n\n%s", digest.Subject, digest.Body)
		return nil
	}
	var errs []error
	if s := n.cfg.SMTP; s != nil {
		var pw string
		if s.Username != "" {
			pw, err = rbclient.ReadSecret(s.PasswordFile)
		}
		if err == nil {
			err = sendMail(ctx, s, pw, digest.Subject, digest.Body)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		} else {
			n.log.Info("email sent", "items", len(due))
		}
	}
	if w := n.cfg.Webhook; w != nil {
		u := w.URL
		var err error
		if w.URLFile != "" {
			u, err = rbclient.ReadSecret(w.URLFile)
		}
		if err == nil {
			err = sendWebhook(ctx, u, text, due)
		}
		if err != nil {
			errs = append(errs, err)
		} else {
			n.log.Info("webhook sent", "items", len(due))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return saveState(n.statePath, next)
}

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr)) }

func realMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rackbook-notify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/rackbook/notify.yml", "path to the config file")
	once := fs.Bool("once", false, "run once and exit")
	dry := fs.Bool("dry-run", false, "print the digest, send nothing and save nothing")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	cfg, err := loadConfig(*cfgPath, *dry)
	if err != nil {
		log.Error("config", "error", err)
		return 1
	}
	n, err := newNotifier(cfg, *dry, stdout, log)
	if err != nil {
		log.Error("setup", "error", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = n.run(ctx)
	if err != nil {
		log.Error("run failed", "error", err)
	}
	if *once {
		if err != nil {
			return 1
		}
		return 0
	}
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("stopping")
			return 0
		case <-t.C:
			if err := n.run(ctx); err != nil && ctx.Err() == nil {
				log.Error("run failed", "error", err)
			}
		}
	}
}
