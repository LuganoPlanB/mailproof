package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/luganoplanb/mailproof/internal/artifact"
	"github.com/luganoplanb/mailproof/internal/budget"
	"github.com/luganoplanb/mailproof/internal/ingress"
	"github.com/luganoplanb/mailproof/internal/queue"
)

var version = "dev"

var errCollectorLeaseHeld = errors.New("collector lease is held")

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

func exitCode(err error) int {
	if errors.Is(err, errCollectorLeaseHeld) {
		return 3
	}
	return 2
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mailproof {version|collect|worker|status|inspect|replay}")
	}
	switch args[0] {
	case "version":
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version})
	case "collect":
		return collect(ctx, args[1:])
	case "worker":
		return worker(ctx, args[1:])
	case "status":
		return status(ctx, args[1:])
	case "inspect":
		return inspect(ctx, args[1:])
	case "replay":
		return replay(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func collect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	source := fs.String("source", "/var/mail/verification/new", "completed Maildir directory")
	artifacts := fs.String("artifacts", "/artifacts", "artifact root")
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	logs := fs.String("postfix-log", "", "restricted Postfix log file")
	registry := fs.String("token-registry", "", "token registry JSON file")
	once := fs.Bool("once", false, "run one sweep")
	watch := fs.Bool("watch", false, "poll every two seconds")
	maxJobs := fs.Int("max-jobs", 0, "maximum collection sweeps")
	maxRuntime := fs.Duration("max-runtime", 0, "maximum runtime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := budget.Default().Validate(); err != nil {
		return fmt.Errorf("validate budgets: %w", err)
	}
	if *once == *watch {
		return errors.New("choose exactly one of --once or --watch")
	}
	if *maxJobs < 0 {
		return errors.New("max-jobs must not be negative")
	}
	if *maxRuntime < 0 {
		return errors.New("max-runtime must not be negative")
	}
	if *maxRuntime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *maxRuntime)
		defer cancel()
	}
	owner, err := randomID()
	if err != nil {
		return err
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	ok, err := queue.AcquireCollectorLease(ctx, db, owner, time.Now(), 30*time.Second)
	if err != nil {
		return err
	}
	if !ok {
		return errCollectorLeaseHeld
	}
	defer queue.ReleaseCollectorLease(context.Background(), db, owner)
	sweeps := 0
	for {
		ok, err := queue.AcquireCollectorLease(ctx, db, owner, time.Now(), 30*time.Second)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("collector lease lost")
		}
		if err := collectOnce(ctx, db, *source, *artifacts, *logs, *registry); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return emitStatus("collect", "stopped", sweeps)
			}
			return err
		}
		sweeps++
		if *once {
			return emitStatus("collect", "completed", sweeps)
		}
		if *maxJobs > 0 && sweeps >= *maxJobs {
			return emitStatus("collect", "completed", sweeps)
		}
		select {
		case <-ctx.Done():
			return emitStatus("collect", "stopped", sweeps)
		case <-time.After(2 * time.Second):
		}
	}
}
func collectOnce(ctx context.Context, db *sql.DB, source, artifacts, logPath, registryPath string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read Maildir: %w", err)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			continue
		}
		sourceKey := filepath.Join(source, entry.Name())
		seen, err := queue.Collected(ctx, db, sourceKey)
		if err != nil {
			return err
		}
		if seen {
			continue
		}
		digest, _, err := artifact.Seal(ctx, artifacts, sourceKey)
		if err != nil {
			return fmt.Errorf("seal %q: %w", entry.Name(), err)
		}
		deliveryID, err := randomID()
		if err != nil {
			return err
		}
		message, err := artifact.ReadHeaders(sourceKey, 64<<10)
		if err != nil {
			return err
		}
		correlation := ingress.Correlate(string(message), readLines(logPath), readRegistry(registryPath))
		if err := publishIngress(artifacts, deliveryID, digest, entry.Name(), correlation); err != nil {
			return err
		}
		runID, err := randomID()
		if err != nil {
			return err
		}
		if err := queue.EnqueueCollection(ctx, db, deliveryID, digest, sourceKey, runID, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

func readLines(path string) []string {
	if path == "" {
		return []string{}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	return strings.Split(string(raw), "\n")
}
func readRegistry(path string) map[string]string {
	values := map[string]string{}
	if path == "" {
		return values
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return values
	}
	_ = json.Unmarshal(raw, &values)
	return values
}
func publishIngress(root, deliveryID, digest, sourceKey string, correlation ingress.Correlation) error {
	dir := filepath.Join(root, "deliveries", deliveryID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create delivery directory: %w", err)
	}
	payload, err := json.Marshal(struct {
		Schema        string `json:"schema"`
		DeliveryID    string `json:"delivery_id"`
		MessageDigest string `json:"message_digest"`
		SourceKey     string `json:"source_maildir_key"`
		Correlation   string `json:"correlation_status"`
		QueueID       string `json:"queue_id,omitempty"`
		TokenHash     string `json:"token_hash,omitempty"`
	}{"mailproof.ingress-context/v1", deliveryID, digest, sourceKey, correlation.Status, correlation.QueueID, correlation.TokenHash})
	if err != nil {
		return fmt.Errorf("encode ingress: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".ingress-*")
	if err != nil {
		return fmt.Errorf("create ingress temporary file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(append(payload, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write ingress: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync ingress: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close ingress: %w", err)
	}
	if err := os.Link(name, filepath.Join(dir, "ingress.json")); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("publish ingress: %w", err)
	}
	return nil
}
func worker(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	drain := fs.Bool("drain", false, "stop when no job is due")
	maxJobs := fs.Int("max-jobs", 0, "maximum jobs to claim")
	maxRuntime := fs.Duration("max-runtime", 0, "maximum runtime")
	concurrency := fs.Int("concurrency", 1, "maximum in-process jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *maxJobs < 0 || *maxRuntime < 0 || *concurrency <= 0 {
		return errors.New("max-jobs and max-runtime must not be negative and concurrency must be positive")
	}
	if *maxRuntime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *maxRuntime)
		defer cancel()
	}
	if err := budget.Default().Validate(); err != nil {
		return err
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	owner, err := randomID()
	if err != nil {
		return err
	}
	idle := time.Second
	processed := 0
	for {
		if *maxJobs > 0 && processed >= *maxJobs {
			return emitStatus("worker", "completed", processed)
		}
		claimed, err := queue.Claim(ctx, db, owner, "analysis", time.Now(), budget.Default().WorkerLease)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return emitStatus("worker", "stopped", processed)
			}
			return err
		}
		if claimed == nil {
			if *drain {
				return emitStatus("worker", "drained", processed)
			}
			select {
			case <-ctx.Done():
				return emitStatus("worker", "stopped", processed)
			case <-time.After(idle):
			}
			if idle < 30*time.Second {
				idle *= 2
				if idle > 30*time.Second {
					idle = 30 * time.Second
				}
			}
			continue
		}
		idle = time.Second
		if err := queue.FinishAnalysis(ctx, db, claimed.ID, owner); err != nil {
			return err
		}
		processed++
	}
}

func emitStatus(command, status string, count int) error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		Command string `json:"command"`
		Status  string `json:"status"`
		Count   int    `json:"count"`
	}{Command: command, Status: status, Count: count})
}
func status(ctx context.Context, args []string) error {
	_ = ctx
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*jsonFlag {
		return errors.New("status requires --json")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version, "status": "ok"})
}
func inspect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	delivery := fs.String("delivery", "", "delivery ID")
	runID := fs.String("run", "", "run ID")
	jsonFlag := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*jsonFlag || (*delivery == "" && *runID == "") {
		return errors.New("inspect requires --json and --delivery or --run")
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	var id, stateValue string
	err = db.QueryRowContext(ctx, "SELECT run_id,state FROM runs WHERE run_id=? OR delivery_id=? ORDER BY created_at LIMIT 1", *runID, *delivery).Scan(&id, &stateValue)
	if err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"run_id": id, "state": stateValue})
}
func replay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	runID := fs.String("run", "", "run ID")
	jsonFlag := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*jsonFlag || *runID == "" {
		return errors.New("replay requires --run and --json")
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	var delivery string
	if err := db.QueryRowContext(ctx, "SELECT delivery_id FROM runs WHERE run_id=?", *runID).Scan(&delivery); err != nil {
		return fmt.Errorf("find replay source: %w", err)
	}
	next, err := randomID()
	if err != nil {
		return err
	}
	if err := queue.Replay(ctx, db, delivery, next, time.Now()); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"run_id": next, "delivery_id": delivery})
}
func randomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
