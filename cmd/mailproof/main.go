package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/luganoplanb/mailproof/internal/admission"
	"github.com/luganoplanb/mailproof/internal/analytics"
	"github.com/luganoplanb/mailproof/internal/analyzers"
	"github.com/luganoplanb/mailproof/internal/artifact"
	"github.com/luganoplanb/mailproof/internal/budget"
	"github.com/luganoplanb/mailproof/internal/control"
	"github.com/luganoplanb/mailproof/internal/dashboard"
	"github.com/luganoplanb/mailproof/internal/evidence"
	"github.com/luganoplanb/mailproof/internal/ingress"
	"github.com/luganoplanb/mailproof/internal/intel"
	"github.com/luganoplanb/mailproof/internal/queue"
	"github.com/luganoplanb/mailproof/internal/report"
	"github.com/luganoplanb/mailproof/internal/results"
	"github.com/luganoplanb/mailproof/internal/submitter"
)

var version = "dev"
var analyticsClock = time.Now

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
		return errors.New("usage: mailproof {version|dashboard|control-api|collect|worker|reporter|intel-projector|intel|analytics-projector|analytics|results-api|status|inspect|replay|bundle|verify-report|redeliver|submitter|admission}")
	}
	switch args[0] {
	case "version":
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version})
	case "collect":
		return collect(ctx, args[1:])
	case "worker":
		return worker(ctx, args[1:])
	case "reporter":
		return reporter(ctx, args[1:])
	case "analytics-projector":
		return analyticsProjector(ctx, args[1:])
	case "intel-projector":
		return intelProjector(ctx, args[1:])
	case "intel":
		return intelCommand(ctx, args[1:])
	case "analytics":
		return analyticsCommand(ctx, args[1:])
	case "results-api":
		return resultsAPI(ctx, args[1:])
	case "dashboard":
		return dashboardCommand(ctx, args[1:])
	case "control-api":
		return controlAPI(ctx, args[1:])
	case "status":
		return status(ctx, args[1:])
	case "inspect":
		return inspect(ctx, args[1:])
	case "replay":
		return replay(ctx, args[1:])
	case "bundle":
		return bundle(args[1:])
	case "verify-report":
		return verifyReport(args[1:])
	case "redeliver":
		return redeliver(ctx, args[1:])
	case "submitter":
		return submitterCommand(ctx, args[1:])
	case "admission":
		return admissionCommand(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func dashboardCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	host := fs.String("host", "127.0.0.1", "listen host")
	port := fs.Int("port", 3000, "listen port")
	publicOrigin := fs.String("public-origin", "", "public browser origin")
	resultsURL := fs.String("results-url", "", "internal results API origin")
	resultsTokenFile := fs.String("results-token-file", "", "results API bearer token file")
	sessionKeyFile := fs.String("session-key-file", "", "dashboard session MAC key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 || *resultsURL == "" || *resultsTokenFile == "" || *sessionKeyFile == "" {
		return errors.New("dashboard requires valid --host, --port, --results-url, --results-token-file, and --session-key-file")
	}
	base, err := url.Parse(*resultsURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("dashboard results URL must be an origin")
	}
	origin := *publicOrigin
	if origin == "" {
		origin = "http://localhost:" + strconv.Itoa(*port)
	}
	browserOrigin, err := url.Parse(origin)
	if err != nil || browserOrigin.Scheme == "" || browserOrigin.Host == "" || browserOrigin.User != nil || browserOrigin.Path != "" || browserOrigin.RawQuery != "" || browserOrigin.Fragment != "" || (browserOrigin.Scheme != "https" && !(browserOrigin.Scheme == "http" && browserOrigin.Hostname() == "localhost")) {
		return errors.New("dashboard public origin must be an allowed absolute origin")
	}
	if !dashboardLoopbackHost(*host) && *publicOrigin == "" {
		return errors.New("dashboard non-loopback bind requires --public-origin")
	}
	token, err := os.ReadFile(*resultsTokenFile)
	if err != nil || len(token) < 32 {
		return errors.New("dashboard results token must contain at least 32 bytes")
	}
	key, err := os.ReadFile(*sessionKeyFile)
	if err != nil || len(key) < 32 {
		return errors.New("dashboard session key must contain at least 32 bytes")
	}
	server := &http.Server{Addr: net.JoinHostPort(*host, strconv.Itoa(*port)), Handler: dashboard.NewWithConfig(dashboard.ResultsClient{BaseURL: base, Token: bytes.TrimSpace(token)}, dashboard.Config{PublicOrigin: browserOrigin, SessionKey: key}), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { <-ctx.Done(); _ = server.Shutdown(context.Background()) }()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func dashboardLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func intelCommand(ctx context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "rebuild" && args[0] != "activate") {
		return errors.New("usage: mailproof intel {rebuild|activate}")
	}
	fs := flag.NewFlagSet("intel "+args[0], flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	version := fs.String("policy-version", intel.PolicyVersion, "projection policy version")
	dryRun := fs.Bool("dry-run", false, "validate without mutation")
	confirm := fs.Bool("confirm", false, "perform the requested mutation")
	keyFile := fs.String("indicator-key-file", "/runtime/secrets/indicator-hmac-key", "indicator HMAC key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dryRun == *confirm || *version == "" {
		return errors.New("intel operation requires exactly one of --dry-run or --confirm and a policy version")
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	if *dryRun {
		return emitStatus("intel-"+args[0], "dry-run", 0)
	}
	if args[0] == "activate" {
		_, err = db.ExecContext(ctx, `UPDATE campaign_projections SET active=CASE WHEN projection_version=? THEN 1 ELSE 0 END`, *version)
		if err != nil {
			return err
		}
		return emitStatus("intel-activate", "completed", 0)
	}
	info, err := os.Stat(*keyFile)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return errors.New("indicator key must be a readable 0600 file")
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil || len(key) < 32 {
		return errors.New("indicator key must contain at least 32 bytes")
	}
	p := intel.Projector{DB: db, CampaignKey: key, PolicyVersion: *version}
	if err := p.RebuildComponents(ctx); err != nil {
		return err
	}
	return emitStatus("intel-rebuild", "completed", 0)
}

func intelProjector(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("intel-projector", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	artifacts := fs.String("artifacts", "/artifacts", "artifact root")
	keyFile := fs.String("indicator-key-file", "/runtime/secrets/indicator-hmac-key", "indicator HMAC key")
	verification := fs.String("verification-key-file", "/runtime/secrets/report-verification-key.pem", "report verification public key")
	once := fs.Bool("once", false, "project one bounded batch and exit")
	watch := fs.Bool("watch", false, "continue projecting")
	batch := fs.Int("batch-size", 25, "outbox rows per transaction (1..25)")
	poll := fs.Duration("poll-interval", time.Second, "idle poll interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *once == *watch || *batch < 1 || *batch > 25 || *poll <= 0 {
		return errors.New("intel-projector requires exactly one of --once or --watch, batch-size 1..25, and positive poll interval")
	}
	// The key is intentionally permission-checked even though signed envelopes
	// already contain fingerprints: a missing/rotated key must not activate a
	// projection version by accident.
	if info, err := os.Stat(*keyFile); err != nil || info.Mode().Perm()&0o077 != 0 {
		return errors.New("indicator key must be a readable 0600 file")
	}
	indicatorKey, err := os.ReadFile(*keyFile)
	if err != nil || len(indicatorKey) < 32 {
		return errors.New("indicator key must contain at least 32 bytes")
	}
	pemBytes, err := os.ReadFile(*verification)
	if err != nil {
		return err
	}
	public, _, err := report.ParsePublicKey(pemBytes)
	if err != nil {
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
	p := intel.Projector{DB: db, Artifacts: *artifacts, Trusted: []ed25519.PublicKey{public}, CampaignKey: indicatorKey}
	for {
		n, err := p.ProjectOnce(ctx, owner, *batch)
		if err != nil {
			return err
		}
		if *once {
			return emitStatus("intel-projector", "completed", n)
		}
		select {
		case <-ctx.Done():
			return emitStatus("intel-projector", "stopped", n)
		case <-time.After(*poll):
		}
	}
}

func analyticsProjector(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("analytics-projector", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	once := fs.Bool("once", false, "project one bounded batch and exit")
	watch := fs.Bool("watch", false, "continue projecting")
	batch := fs.Int("batch-size", 100, "events per transaction (1..1000)")
	poll := fs.Duration("poll-interval", time.Second, "idle poll interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *once == *watch || *poll <= 0 {
		return errors.New("analytics-projector requires exactly one of --once or --watch and a positive poll interval")
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
	ok, err := acquireAnalyticsLease(ctx, db, owner, time.Now(), 30*time.Second)
	if err != nil {
		return err
	}
	if !ok {
		return errCollectorLeaseHeld
	}
	defer releaseAnalyticsLease(context.Background(), db, owner)
	for {
		ok, err := acquireAnalyticsLease(ctx, db, owner, time.Now(), 30*time.Second)
		if err != nil {
			return err
		}
		if !ok {
			return errCollectorLeaseHeld
		}
		n, err := analytics.ProjectOnce(ctx, db, *batch)
		if err != nil {
			return err
		}
		if *once {
			return emitStatus("analytics-projector", "completed", n)
		}
		select {
		case <-ctx.Done():
			return emitStatus("analytics-projector", "stopped", n)
		case <-time.After(*poll):
		}
	}
}

func acquireAnalyticsLease(ctx context.Context, db *sql.DB, owner string, now time.Time, duration time.Duration) (bool, error) {
	r, err := db.ExecContext(ctx, `INSERT INTO analytics_projector_lease(singleton,owner,until) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET owner=excluded.owner,until=excluded.until WHERE analytics_projector_lease.until < ? OR analytics_projector_lease.owner=excluded.owner`, owner, now.Add(duration).Unix(), now.Unix())
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func releaseAnalyticsLease(ctx context.Context, db *sql.DB, owner string) {
	_, _ = db.ExecContext(ctx, "DELETE FROM analytics_projector_lease WHERE singleton=1 AND owner=?", owner)
}

func analyticsCommand(ctx context.Context, args []string) error {
	if len(args) < 1 || (args[0] != "rebuild" && args[0] != "retain") {
		return errors.New("usage: mailproof analytics {rebuild|retain} --state=... --dry-run|--confirm")
	}
	fs := flag.NewFlagSet("analytics "+args[0], flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	dry := fs.Bool("dry-run", false, "show action without changing state")
	confirm := fs.Bool("confirm", false, "perform action")
	from := fs.String("from", "", "UTC inclusive start")
	to := fs.String("to", "", "UTC exclusive end")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dry == *confirm {
		return errors.New("exactly one of --dry-run or --confirm is required")
	}
	parseUTC := func(value string) (time.Time, error) {
		if value == "" {
			return time.Time{}, nil
		}
		if !strings.HasSuffix(value, "Z") {
			return time.Time{}, errors.New("analytics bounds must be RFC3339 UTC")
		}
		v, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, errors.New("analytics bounds must be RFC3339 UTC")
		}
		return v.UTC(), nil
	}
	start, err := parseUTC(*from)
	if err != nil {
		return err
	}
	end, err := parseUTC(*to)
	if err != nil {
		return err
	}
	if (!start.IsZero()) != (!end.IsZero()) {
		return errors.New("analytics rebuild requires both --from and --to")
	}
	if !start.IsZero() && !start.Before(end) {
		return errors.New("analytics rebuild requires --from before --to")
	}
	if !start.IsZero() && (start.Unix()%86400 != 0 || end.Unix()%86400 != 0) {
		return errors.New("analytics rebuild bounds must align to UTC day buckets")
	}
	if args[0] == "retain" && (!start.IsZero() || !end.IsZero()) {
		return errors.New("analytics retain does not accept --from/--to")
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	if *dry && args[0] == "rebuild" {
		var events int
		if start.IsZero() {
			err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM analytics_events").Scan(&events)
		} else {
			err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM analytics_events WHERE occurred_at>=? AND occurred_at<?", start.Unix(), end.Unix()).Scan(&events)
		}
		if err != nil {
			return err
		}
		return emitStatus("analytics "+args[0], "dry-run", events)
	}
	if args[0] == "rebuild" {
		if !start.IsZero() {
			if err := analytics.RebuildWindow(ctx, db, start, end); err != nil {
				return err
			}
			return emitStatus("analytics rebuild", "completed", 0)
		}
		var first, last int64
		if err := db.QueryRowContext(ctx, "SELECT COALESCE(MIN(occurred_at),0),COALESCE(MAX(occurred_at),0) FROM analytics_events").Scan(&first, &last); err != nil {
			return err
		}
		if first != 0 {
			begin := time.Unix(first, 0).UTC().Truncate(24 * time.Hour)
			end := time.Unix(last, 0).UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
			if err := analytics.RebuildWindow(ctx, db, begin, end); err != nil {
				return err
			}
		}
		return emitStatus("analytics rebuild", "completed", 0)
	}
	var backup, cursor, newest int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM analytics_backup_markers WHERE verified_at>0 AND manifest_digest<>''").Scan(&backup); err != nil {
		return err
	}
	if backup == 0 {
		return errors.New("analytics retention requires verified backup marker")
	}
	if err := db.QueryRowContext(ctx, "SELECT event_id FROM analytics_cursor WHERE singleton=1").Scan(&cursor); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(event_id),0) FROM analytics_events").Scan(&newest); err != nil {
		return err
	}
	if newest > cursor {
		return errors.New("analytics retention refuses unprojected events")
	}
	now := analyticsClock().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var incomplete int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM metric_rollups m WHERE m.granularity='minute' AND m.bucket_start<? AND NOT EXISTS (SELECT 1 FROM metric_rollups h WHERE h.granularity='hour' AND h.metric=m.metric AND h.outcome=m.outcome AND h.schema_version=m.schema_version AND h.dimension_key=m.dimension_key AND h.bucket_start=(m.bucket_start/3600)*3600)`, now.AddDate(0, 0, -31).Unix()).Scan(&incomplete); err != nil {
		return err
	}
	if incomplete != 0 {
		return errors.New("analytics retention refuses incomplete hourly rollups")
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM metric_rollups h WHERE h.granularity='hour' AND h.bucket_start<? AND NOT EXISTS (SELECT 1 FROM metric_rollups d WHERE d.granularity='day' AND d.metric=h.metric AND d.outcome=h.outcome AND d.schema_version=h.schema_version AND d.dimension_key=h.dimension_key AND d.bucket_start=(h.bucket_start/86400)*86400)`, now.AddDate(0, 0, -366).Unix()).Scan(&incomplete); err != nil {
		return err
	}
	if incomplete != 0 {
		return errors.New("analytics retention refuses incomplete daily rollups")
	}
	if *dry {
		var eligible int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM analytics_events WHERE occurred_at<? AND event_id<=?", now.AddDate(0, 0, -31).Unix(), cursor).Scan(&eligible); err != nil {
			return err
		}
		return emitStatus("analytics retain", "dry-run", eligible)
	}
	// Explicit allow-list: only these analytics projections and source events
	// are mutable. Lifecycle/result/decision/campaign/policy/audit authority is
	// intentionally not named by any retention statement.
	if _, err = tx.ExecContext(ctx, "DELETE FROM metric_rollups WHERE granularity='minute' AND bucket_start<?", now.AddDate(0, 0, -31).Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM metric_rollups WHERE granularity='hour' AND bucket_start<?", now.AddDate(0, 0, -366).Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM metric_rollups WHERE granularity='day' AND bucket_start<?", now.AddDate(-5, 0, 0).Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM analytics_events WHERE occurred_at<? AND event_id<=?", now.AddDate(0, 0, -31).Unix(), cursor); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return emitStatus("analytics retain", "completed", 0)
}

func controlAPI(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("control-api", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8081", "loopback-only internal HTTP listen address")
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	tokenFile := fs.String("token-file", "/runtime/secrets/control-api-token", "0600 bearer token file")
	confirmationFile := fs.String("confirmation-key-file", "/runtime/secrets/control-confirmation-hmac-key", "0600 confirmation HMAC key file")
	capabilityFile := fs.String("capability-key-file", "/runtime/secrets/capability-hmac-key", "0600 capability HMAC key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := controlLoopbackAddress(*listen); err != nil {
		return err
	}
	readKey := func(path, name string) ([]byte, error) {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", name, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New(name + " must not be group or world readable")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		b = bytes.TrimSpace(b)
		if len(b) < 32 {
			return nil, errors.New(name + " is too short")
		}
		return b, nil
	}
	token, err := readKey(*tokenFile, "control API token")
	if err != nil {
		return err
	}
	confirmation, err := readKey(*confirmationFile, "confirmation HMAC key")
	if err != nil {
		return err
	}
	capability, err := readKey(*capabilityFile, "capability HMAC key")
	if err != nil {
		return err
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	server := &http.Server{Addr: *listen, Handler: control.API{Service: control.Service{DB: db, ConfirmationKey: confirmation, CapabilityKey: capability, CapabilityDomain: "mailproof.test"}, Token: token}.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve control API: %w", err)
}

// controlLoopbackAddress protects bearer-authenticated control endpoints from
// accidental exposure outside the local host.
func controlLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return errors.New("control API listen address must be a loopback host and port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("control API listen address has an invalid port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("control API must bind only to a loopback address")
	}
	return nil
}

func resultsAPI(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("results-api", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	listen := fs.String("listen", ":8080", "internal HTTP listen address")
	tokenPath := fs.String("token-file", "/runtime/secrets/results-api-token", "0600 bearer token file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	info, err := os.Stat(*tokenPath)
	if err != nil {
		return fmt.Errorf("stat API token: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("API token file must not be group or world readable")
	}
	token, err := os.ReadFile(*tokenPath)
	if err != nil {
		return fmt.Errorf("read API token: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) < 32 {
		return errors.New("API token is too short")
	}
	db, err := queue.OpenReadOnly(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	repo := results.Repository{DB: db, CursorKey: token}
	server := &http.Server{Addr: *listen, Handler: results.API{Repository: repo, Dashboard: analytics.Repository{DB: db}, Token: token}.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve results API: %w", err)
}

func admissionCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admission", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	capabilityKey := fs.String("capability-key", "/runtime/secrets/capability-hmac-key", "capability HMAC key")
	stampKey := fs.String("stamp-key", "/runtime/secrets/admission-stamp-hmac-key", "admission stamp HMAC key")
	domain := fs.String("domain", "mailproof.test", "submission address domain")
	listen := fs.String("listen", ":10040", "Postfix policy listener")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cap, err := os.ReadFile(*capabilityKey)
	if err != nil {
		return fmt.Errorf("read capability HMAC key: %w", err)
	}
	stamp, err := os.ReadFile(*stampKey)
	if err != nil {
		return fmt.Errorf("read admission stamp HMAC key: %w", err)
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	policies := &admission.SnapshotStore{DB: db}
	if err := policies.Refresh(ctx); err != nil {
		return fmt.Errorf("load admission policy snapshot: %w", err)
	}
	go policies.Poll(ctx)
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen admission policy: %w", err)
	}
	defer listener.Close()
	return (admission.Server{Service: admission.Service{DB: db, CapabilityKey: cap, StampKey: stamp, Domain: *domain, Resolver: admission.DNSResolver{Server: "unbound:53", Timeout: 2 * time.Second}, PolicyStore: policies}, MaxConnections: 32}).Serve(ctx, listener)
}

// postfixMailer is the concrete adapter; enrollment itself only knows Mailer.
type postfixMailer struct{ address string }

func (m postfixMailer) Send(_ context.Context, to, subject, body string) error {
	sum := sha256.Sum256([]byte(to + "\x00" + body))
	message := "To: " + to + "\r\nSubject: " + subject + "\r\nMessage-ID: <mailproof-enrollment-" + hex.EncodeToString(sum[:16]) + "@mailproof>\r\n\r\n" + body
	return smtp.SendMail(m.address, nil, "", []string{to}, []byte(message))
}

func submitterCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mailproof submitter {challenge|activate|list|revoke|rotate}")
	}
	fs := flag.NewFlagSet("submitter "+args[0], flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	key := fs.String("capability-key", "/runtime/secrets/capability-hmac-key", "capability HMAC key")
	keyID := fs.String("capability-key-id", "v1", "capability HMAC key identifier")
	domain := fs.String("domain", "mailproof.test", "submission address domain")
	smtpAddress := fs.String("smtp-addr", "postfix:25", "internal Postfix SMTP address")
	email := fs.String("email", "", "submitter mailbox address")
	code := fs.String("code", "", "mailbox challenge code")
	id := fs.String("id", "", "submitter ID")
	dryRun := fs.Bool("dry-run", false, "show action without changing state")
	confirm := fs.Bool("confirm", false, "perform state-changing action")
	jsonFlag := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if !*jsonFlag {
		return errors.New("submitter commands require --json")
	}
	if args[0] != "list" && *dryRun == *confirm {
		return errors.New("state-changing submitter commands require exactly one of --dry-run or --confirm")
	}
	if args[0] == "list" && (*dryRun || *confirm) {
		return errors.New("submitter list does not accept --dry-run or --confirm")
	}
	encode := func(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
	if *dryRun {
		switch args[0] {
		case "challenge":
			if _, err := submitter.CanonicalAddress(*email); err != nil {
				return err
			}
			return encode(map[string]any{"email": *email, "would_challenge": true})
		case "activate":
			if _, err := submitter.CanonicalAddress(*email); err != nil || *code == "" {
				return errors.New("submitter activate requires --email and --code")
			}
			return encode(map[string]any{"email": *email, "would_activate": true})
		case "revoke", "rotate":
			if !safeID(*id) {
				return fmt.Errorf("submitter %s requires a valid --id", args[0])
			}
			return encode(map[string]any{"submitter_id": *id, "would_" + args[0]: true})
		default:
			return fmt.Errorf("unknown submitter command %q", args[0])
		}
	}
	keyBytes, err := os.ReadFile(*key)
	if err != nil {
		return fmt.Errorf("read capability HMAC key: %w", err)
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	svc := submitter.Service{DB: db, Mailer: postfixMailer{address: *smtpAddress}, CapabilityKey: keyBytes, CapabilityKeyID: *keyID, Domain: *domain}
	switch args[0] {
	case "challenge":
		if *email == "" {
			return errors.New("submitter challenge requires --email")
		}
		challenge, err := svc.Challenge(ctx, *email)
		if err != nil {
			return err
		}
		return encode(map[string]any{"challenge_id": challenge.ID, "submitter_id": challenge.SubmitterID, "expires_at": challenge.ExpiresAt})
	case "activate":
		if *email == "" || *code == "" {
			return errors.New("submitter activate requires --email and --code")
		}
		a, err := svc.Activate(ctx, *email, *code)
		if err != nil {
			return err
		}
		return encode(map[string]any{"submitter": a.Submitter, "submission_address": a.SubmissionAddress})
	case "list":
		items, err := svc.List(ctx)
		if err != nil {
			return err
		}
		return encode(items)
	case "revoke":
		if !safeID(*id) {
			return errors.New("submitter revoke requires a valid --id")
		}
		if err := svc.Revoke(ctx, *id); err != nil {
			return err
		}
		return encode(map[string]any{"submitter_id": *id, "status": "revoked"})
	case "rotate":
		if !safeID(*id) {
			return errors.New("submitter rotate requires a valid --id")
		}
		a, err := svc.Rotate(ctx, *id)
		if err != nil {
			return err
		}
		return encode(map[string]any{"submitter_id": *id, "submission_address": a})
	default:
		return fmt.Errorf("unknown submitter command %q", args[0])
	}
}

func bundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	artifacts := fs.String("artifacts", "/artifacts", "artifact root")
	runID := fs.String("run", "", "run ID")
	output := fs.String("output", "", "bundle directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !safeID(*runID) || *output == "" {
		return errors.New("bundle requires a valid --run and --output")
	}
	if err := os.MkdirAll(*output, 0o750); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}
	for _, name := range []string{"report.json", "report.txt", "report.html", "manifest.json", "manifest.sig"} {
		source := filepath.Join(*artifacts, "runs", *runID, "report", name)
		destination := filepath.Join(*output, name)
		if err := copyFixed(source, destination); err != nil {
			return err
		}
	}
	return nil
}

func verifyReport(args []string) error {
	fs := flag.NewFlagSet("verify-report", flag.ContinueOnError)
	bundleDir := fs.String("bundle", "", "offline bundle directory")
	keys := fs.String("keys", "", "trusted public-key directory")
	jsonFlag := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundleDir == "" || *keys == "" || !*jsonFlag {
		return errors.New("verify-report requires --bundle, --keys, and --json")
	}
	trusted, err := report.ReadTrustedPublicKeys(*keys)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report.VerifyBundle(*bundleDir, trusted))
}

func redeliver(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("redeliver", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	runID := fs.String("run", "", "run ID")
	dryRun := fs.Bool("dry-run", false, "show eligible action")
	confirm := fs.Bool("confirm", false, "return a dead report to the queue")
	jsonFlag := fs.Bool("json", false, "emit JSON")
	duplicateRisk := fs.Bool("accept-duplicate-risk", false, "acknowledge unknown post-DATA outcome")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !safeID(*runID) || !*jsonFlag || *dryRun == *confirm {
		return errors.New("redeliver requires --run, --json, and exactly one of --dry-run or --confirm")
	}
	db, err := queue.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer db.Close()
	var stateValue, lastError string
	if err := db.QueryRowContext(ctx, "SELECT state,last_error FROM runs WHERE run_id=?", *runID).Scan(&stateValue, &lastError); err != nil {
		return fmt.Errorf("find report run: %w", err)
	}
	if stateValue != queue.ReportDead {
		return errors.New("redelivery allowed only from report_dead")
	}
	if strings.Contains(lastError, "smtp_outcome_unknown") && !*duplicateRisk {
		return errors.New("unknown SMTP outcome requires --accept-duplicate-risk after Postfix log reconciliation")
	}
	if *confirm {
		if err := queue.Redeliver(ctx, db, *runID); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"run_id": *runID, "state": map[bool]string{true: queue.ReportPending, false: queue.ReportDead}[*confirm]})
}

func safeID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func copyFixed(source, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("bundle destination exists: %s", filepath.Base(destination))
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect bundle destination: %w", err)
	}
	contents, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read bundle artifact %s: %w", filepath.Base(source), err)
	}
	if err := os.WriteFile(destination, contents, 0o440); err != nil {
		return fmt.Errorf("write bundle artifact %s: %w", filepath.Base(destination), err)
	}
	return nil
}
func collect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	source := fs.String("source", "/var/mail/verification/new", "completed Maildir directory")
	artifacts := fs.String("artifacts", "/artifacts", "artifact root")
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	logs := fs.String("postfix-log", "", "restricted Postfix log file")
	registry := fs.String("token-registry", "", "token registry JSON file")
	stampKeyPath := fs.String("admission-stamp-key", "/runtime/secrets/admission-stamp-hmac-key", "admission stamp HMAC key")
	subjectAllowlistPath := fs.String("subject-domain-allowlist", "", "newline-delimited selected subject domain allowlist")
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
	if *subjectAllowlistPath != "" {
		if err := admission.BootstrapImport(ctx, db, *subjectAllowlistPath, time.Now().UTC()); err != nil {
			return fmt.Errorf("bootstrap selected subject policy: %w", err)
		}
	}
	policies := &admission.SnapshotStore{DB: db}
	if err := policies.Refresh(ctx); err != nil {
		return fmt.Errorf("load collector policy snapshot: %w", err)
	}
	go policies.Poll(ctx)
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
		if err := collectOnce(ctx, db, *source, *artifacts, *logs, *registry, *stampKeyPath, policies); err != nil {
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
func collectOnce(ctx context.Context, db *sql.DB, source, artifacts, logPath, registryPath, stampKeyPath string, policies *admission.SnapshotStore) error {
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
		stampKey, keyErr := os.ReadFile(stampKeyPath)
		if keyErr != nil {
			return fmt.Errorf("read admission stamp HMAC key: %w", keyErr)
		}
		admissionContext := admission.Service{DB: db, StampKey: stampKey}
		decision, admissionErr := admissionContext.ConsumeStamp(ctx, headerPrefix(message), correlation.QueueID)
		if admissionErr != nil {
			decisionID, idErr := randomID()
			if idErr != nil {
				return idErr
			}
			if err := queue.RecordRejectedCollection(ctx, db, deliveryID, digest, sourceKey, decisionID, "admission_stamp_invalid", time.Now()); err != nil {
				return err
			}
			continue
		}
		destination, destinationErr := queue.SnapshotReportDestination(ctx, db, decision.SubmitterID)
		if destinationErr != nil {
			return fmt.Errorf("snapshot admitted delivery destination: %w", destinationErr)
		}
		wrapperFrom, wrapperErr := admission.SelectedSubjectFrom(message)
		if wrapperErr != nil || wrapperFrom != decision.Envelope {
			decisionID, idErr := randomID()
			if idErr != nil {
				return idErr
			}
			if err := queue.RecordAdmittedRejectedCollection(ctx, db, deliveryID, digest, sourceKey, decisionID, "wrapper_sender_invalid", destination, time.Now()); err != nil {
				return err
			}
			if err := queue.EnqueueVerifiedRejectionNotification(ctx, db, decision.ID, deliveryID, decisionID+"-notify", time.Now()); err != nil {
				return err
			}
			continue
		}
		sealed, readErr := os.ReadFile(filepath.Join(artifacts, "messages", digest+".eml"))
		if readErr != nil {
			return fmt.Errorf("read sealed delivery: %w", readErr)
		}
		selection, selectionErr := evidence.SelectTopLevelRFC822(sealed, digest, artifacts)
		if selectionErr != nil {
			return fmt.Errorf("select subject: %w", selectionErr)
		}
		if selection.SubjectDigest == "" && selection.SelectionError == "" {
			selection.SubjectDigest = digest
		}
		if selection.SelectionError != "" {
			decisionID, idErr := randomID()
			if idErr != nil {
				return idErr
			}
			if err := queue.RecordAdmittedRejectedCollection(ctx, db, deliveryID, digest, sourceKey, decisionID, "selected_subject_ambiguous", destination, time.Now()); err != nil {
				return err
			}
			continue
		}
		selected, readErr := os.ReadFile(filepath.Join(artifacts, "messages", selection.SubjectDigest+".eml"))
		if readErr != nil {
			return fmt.Errorf("read sealed selected subject: %w", readErr)
		}
		selectedFrom, selectedErr := admission.SelectedSubjectFrom(selected)
		preflight := admission.Preflight(policies.Snapshot(), selectedFrom, nil, time.Now().UTC())
		if selectedErr != nil || !preflight.Allowed {
			decisionID, idErr := randomID()
			if idErr != nil {
				return idErr
			}
			if err := queue.RecordAdmittedRejectedCollectionWithPolicyRule(ctx, db, deliveryID, digest, sourceKey, decisionID, "selected_subject_sender_denied", destination, preflight.PolicyVersion, preflight.RuleID, time.Now()); err != nil {
				return err
			}
			if err := queue.EnqueueVerifiedRejectionNotification(ctx, db, decision.ID, deliveryID, decisionID+"-notify", time.Now()); err != nil {
				return err
			}
			continue
		}
		runID, err := randomID()
		if err != nil {
			return err
		}
		if err := queue.EnqueueAdmittedCollection(ctx, db, deliveryID, digest, sourceKey, runID, destination, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

func headerPrefix(message []byte) []string {
	lines := []string{}
	for _, line := range strings.Split(string(message), "\n") {
		if line == "\r" || line == "" {
			break
		}
		lines = append(lines, line)
	}
	return lines
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
	artifacts := fs.String("artifacts", "/artifacts", "artifact root")
	rspamdEndpoint := fs.String("rspamd", "http://rspamd:11333/checkv3", "Rspamd checkv3 endpoint")
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
		analysisStarted := time.Now()
		if err := analyzeRun(ctx, db, claimed, *artifacts, *rspamdEndpoint); err != nil {
			if retryErr := queue.Retry(ctx, db, claimed.ID, "analysis", err.Error(), time.Now().Add(time.Second), 3); retryErr != nil {
				return retryErr
			}
			processed++
			continue
		}
		if err := queue.FinishAnalysisMeasured(ctx, db, claimed.ID, owner, time.Since(analysisStarted)); err != nil {
			return err
		}
		processed++
	}
}

func analyzeRun(ctx context.Context, db *sql.DB, run *queue.Run, root, rspamdEndpoint string) error {
	var deliveredDigest string
	if err := db.QueryRowContext(ctx, "SELECT message_digest FROM deliveries WHERE delivery_id=?", run.DeliveryID).Scan(&deliveredDigest); err != nil {
		return fmt.Errorf("find delivery digest: %w", err)
	}
	message, err := os.ReadFile(filepath.Join(root, "messages", deliveredDigest+".eml"))
	if err != nil {
		return fmt.Errorf("read sealed message: %w", err)
	}
	selection, err := evidence.SelectTopLevelRFC822(message, deliveredDigest, root)
	if err != nil {
		return err
	}
	if selection.SubjectDigest == "" && selection.SelectionError == "" {
		selection.SubjectDigest = deliveredDigest
		selection.Scope = evidence.LocalIngress
	}
	if err := publishJSON(filepath.Join(root, "deliveries", run.DeliveryID, "subjects.json"), selection); err != nil {
		return err
	}
	items := []evidence.Evidence{}
	contradictions := []evidence.Contradiction{}
	if selection.SelectionError != "" {
		items = append(items, unavailableEvidence("subject-selection", deliveredDigest, selection.SelectionError))
	} else {
		subject, readErr := os.ReadFile(filepath.Join(root, "messages", selection.SubjectDigest+".eml"))
		if readErr != nil {
			return fmt.Errorf("read selected subject: %w", readErr)
		}
		request := analyzers.RspamdRequest{Scope: selection.Scope, Message: subject, SubjectDigest: selection.SubjectDigest, ConfigDigest: runtimeDigest(), AdapterVersion: "checkv3"}
		normalized, scanErr := (analyzers.RspamdClient{Endpoint: rspamdEndpoint, MaxBytes: 8 << 20}).Analyze(ctx, request)
		if scanErr != nil {
			items = append(items, unavailableEvidence("rspamd", selection.SubjectDigest, scanErr.Error()))
		} else {
			items = append(items, normalized.Evidence(request, "", time.Now())...)
		}
		projection, projectErr := evidence.Project(subject, selection.SubjectDigest)
		if projectErr == nil {
			contradictions = append(contradictions, evidence.SenderAmbiguities(projection)...)
		}
	}
	verdict := evidence.Decide(selection.Scope, items, contradictions)
	if selection.SelectionError != "" {
		verdict = evidence.Verdict{Category: evidence.Indeterminate, Technical: "indeterminate", Behavior: "indeterminate", Unavailable: []string{"subject-selection"}, Rules: []string{"multiple-top-level-rfc822"}, Support: []string{}, Contradictions: []string{}}
	}
	return evidence.PublishAnalysis(root, run.ID, items, verdict)
}

func unavailableEvidence(id, digest, reason string) evidence.Evidence {
	return evidence.Evidence{ID: id, Category: id, Adapter: "mailproof", AdapterVersion: version, ConfigDigest: runtimeDigest(), SubjectDigest: digest, InputDigest: digest, ObservedAt: time.Now().UTC(), Value: json.RawMessage(`{"status":"unavailable"}`), Status: evidence.Unavailable, Authority: evidence.Weak, Limitations: []string{}, Error: reason}
}

func runtimeDigest() string {
	sum := sha256.Sum256([]byte("mailproof-runtime-v1"))
	return hex.EncodeToString(sum[:])
}

func publishJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o440)
}

func reporter(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reporter", flag.ContinueOnError)
	state := fs.String("state", "/state/mailproof.sqlite", "SQLite state database")
	artifacts := fs.String("artifacts", "/artifacts", "artifact root")
	keyPath := fs.String("signing-key", "/runtime/secrets/report-signing-key.pem", "Ed25519 signing key")
	recipientPath := fs.String("report-recipient-file", "/runtime/config/report-recipient", "registered report recipient")
	smtpAddress := fs.String("smtp", "postfix:25", "internal Postfix submission listener")
	drain := fs.Bool("drain", false, "stop when no report is due")
	if err := fs.Parse(args); err != nil {
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
	for {
		run, err := queue.Claim(ctx, db, owner, "report", time.Now(), budget.Default().WorkerLease)
		if err != nil {
			return err
		}
		if run == nil {
			if *drain {
				return emitStatus("reporter", "drained", 0)
			}
			select {
			case <-ctx.Done():
				return emitStatus("reporter", "stopped", 0)
			case <-time.After(time.Second):
				continue
			}
		}
		terminal, unknown, err := reportRun(ctx, db, run, *artifacts, *keyPath, *recipientPath, *smtpAddress)
		if err != nil {
			if unknown {
				err = queue.QuarantineReply(ctx, db, run.ID, owner, "smtp_outcome_unknown: "+err.Error())
			} else {
				err = queue.Retry(ctx, db, run.ID, "report", err.Error(), time.Now().Add(time.Second), 3)
			}
			if err != nil {
				return err
			}
			continue
		}
		if err := queue.FinishReport(ctx, db, run.ID, owner, terminal); err != nil {
			return err
		}
	}
}

func reportRun(ctx context.Context, db *sql.DB, run *queue.Run, root, keyPath, recipientPath, smtpAddress string) (string, bool, error) {
	var digest string
	if err := db.QueryRowContext(ctx, "SELECT message_digest FROM deliveries WHERE delivery_id=?", run.DeliveryID).Scan(&digest); err != nil {
		return "", false, err
	}
	var verdict evidence.Verdict
	if raw, err := os.ReadFile(filepath.Join(root, "runs", run.ID, "analysis", "verdict.json")); err != nil || json.Unmarshal(raw, &verdict) != nil {
		return "", false, errors.New("read analysis verdict")
	}
	evidenceBytes, err := os.ReadFile(filepath.Join(root, "runs", run.ID, "analysis", "evidence.json"))
	if err != nil {
		return "", false, errors.New("read analysis evidence")
	}
	// Analyzer output is not promoted here: absent a typed safe-evidence adapter,
	// report publication explicitly records unavailable values rather than parsing
	// raw evidence, mail, or display strings in the reporter.
	campaignEvidence := &report.CampaignEvidence{Schema: report.CampaignEvidenceSchema, NormalizationVersion: intel.NormalizationVersion, PolicyVersion: "v1", SourceArtifactDigest: evidence.Digest(evidenceBytes), Availability: []report.CampaignAvailability{{Type: "risky_landing_domain", Reason: "unavailable"}, {Type: "redirect_domain", Reason: "unavailable"}, {Type: "selected_from_domain", Reason: "unavailable"}, {Type: "dkim_domain", Reason: "unavailable"}, {Type: "attachment_sha256", Reason: "unavailable"}, {Type: "subject_fingerprint", Reason: "unavailable"}}}
	reportInput := report.Input{RunID: run.ID, DeliveryID: run.DeliveryID, DeliveredOriginalDigest: digest, AuthContextScope: evidence.LocalIngress, Verdict: verdict, PolicyVersion: "v1", ToolVersions: []string{version}, MissingAnalyzers: verdict.Unavailable, Timeline: []report.TimelineEvent{{Kind: "analysis", Claim: "sealed analysis published"}}, CampaignEvidence: campaignEvidence}
	documents, err := report.Publish(root, reportInput)
	if err != nil {
		return "", false, err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", false, err
	}
	key, _, err := report.ParsePrivateKey(keyBytes)
	if err != nil {
		return "", false, err
	}
	manifest := report.Manifest{Schema: report.ManifestSchema, DeliveryID: run.DeliveryID, DeliveredOriginal: digest, ReportJSON: evidence.Digest(documents["report.json"]), ReportText: evidence.Digest(documents["report.txt"]), ReportHTML: evidence.Digest(documents["report.html"]), Policy: runtimeDigest(), Config: runtimeDigest(), IssuedAt: time.Now().UTC(), KeyID: "pending"}
	if err := report.SignAndPublish(root, run.ID, manifest, key); err != nil {
		return "", false, err
	}
	// The projection is deliberately written only after a signed bundle exists
	// and verifies against the public half of the reporter key.
	bundleDir := filepath.Join(root, "runs", run.ID, "report")
	if verification := report.VerifyBundle(bundleDir, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}); !verification.Valid {
		return "", false, errors.New("verify signed report bundle")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err != nil {
		return "", false, err
	}
	if err := results.InsertRecord(ctx, db, results.Record{RunID: run.ID, DeliveryID: run.DeliveryID, OccurredAt: time.Now().UTC(), Verdict: string(verdict.Category), PolicyVersion: "v1", SchemaVersion: "mailproof.result/v1", AuthScope: string(evidence.LocalIngress), SelectedSubjectStatus: "selected", UnavailableAnalyzers: len(verdict.Unavailable), RiskSummary: verdict.Technical, CategorySummary: verdict.Behavior, ManifestDigest: evidence.Digest(manifestBytes), ManifestPath: filepath.Join("runs", run.ID, "report", "manifest.json"), SourceArtifactDigests: evidence.Digest(documents["report.json"])}); err != nil {
		return "", false, err
	}
	_ = recipientPath // retained for CLI compatibility; it is never a routing fallback.
	destination, err := queue.ReportDestinationForRun(ctx, db, run.ID)
	if errors.Is(err, queue.ErrNoReportDestination) {
		return queue.ReplySuppressed, false, nil
	}
	if err != nil {
		return "", false, err
	}
	attemptID, err := queue.BeginReportAttempt(ctx, db, run.ID, destination, time.Now())
	if err != nil {
		return "", false, err
	}
	// manifestBytes was just verified before the immutable projection was made.
	signature, err := os.ReadFile(filepath.Join(root, "runs", run.ID, "report", "manifest.sig"))
	if err != nil {
		_ = queue.FinishReportAttempt(ctx, db, attemptID, "failed", "smtp", time.Now())
		return "", false, err
	}
	unknown, err := report.Submit(ctx, smtpAddress, report.Reply{EnvelopeFrom: "", Recipient: destination.ReplyAddress, DeliveryID: run.DeliveryID, Manifest: manifestBytes, Signature: signature, ReportText: documents["report.txt"], ReportHTML: documents["report.html"], ReportJSON: documents["report.json"]})
	if err != nil {
		outcome := "failed"
		if unknown {
			outcome = "unknown"
		}
		if finishErr := queue.FinishReportAttempt(ctx, db, attemptID, outcome, "smtp", time.Now()); finishErr != nil {
			return "", unknown, finishErr
		}
		return "", unknown, err
	}
	if err := queue.FinishReportAttempt(ctx, db, attemptID, "accepted", "", time.Now()); err != nil {
		return "", false, err
	}
	return queue.Complete, false, nil
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
