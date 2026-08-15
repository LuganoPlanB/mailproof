package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/luganoplanb/mailproof/internal/admission"
	"github.com/luganoplanb/mailproof/internal/analyzers"
	"github.com/luganoplanb/mailproof/internal/artifact"
	"github.com/luganoplanb/mailproof/internal/budget"
	"github.com/luganoplanb/mailproof/internal/evidence"
	"github.com/luganoplanb/mailproof/internal/ingress"
	"github.com/luganoplanb/mailproof/internal/queue"
	"github.com/luganoplanb/mailproof/internal/report"
	"github.com/luganoplanb/mailproof/internal/submitter"
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
		return errors.New("usage: mailproof {version|collect|worker|reporter|status|inspect|replay|bundle|verify-report|redeliver|submitter|admission}")
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
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen admission policy: %w", err)
	}
	defer listener.Close()
	return (admission.Server{Service: admission.Service{DB: db, CapabilityKey: cap, StampKey: stamp, Domain: *domain, Resolver: admission.DNSResolver{Server: "unbound:53", Timeout: 2 * time.Second}}, MaxConnections: 32}).Serve(ctx, listener)
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
	subjectAllowlist, err := readAllowlist(*subjectAllowlistPath)
	if err != nil {
		return err
	}
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
		if err := collectOnce(ctx, db, *source, *artifacts, *logs, *registry, *stampKeyPath, subjectAllowlist); err != nil {
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
func collectOnce(ctx context.Context, db *sql.DB, source, artifacts, logPath, registryPath, stampKeyPath string, subjectAllowlist []string) error {
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
		wrapperFrom, wrapperErr := admission.SelectedSubjectFrom(message)
		if wrapperErr != nil || wrapperFrom != decision.Envelope {
			decisionID, idErr := randomID()
			if idErr != nil {
				return idErr
			}
			if err := queue.RecordRejectedCollection(ctx, db, deliveryID, digest, sourceKey, decisionID, "wrapper_sender_invalid", time.Now()); err != nil {
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
			if err := queue.RecordRejectedCollection(ctx, db, deliveryID, digest, sourceKey, decisionID, "selected_subject_ambiguous", time.Now()); err != nil {
				return err
			}
			continue
		}
		selected, readErr := os.ReadFile(filepath.Join(artifacts, "messages", selection.SubjectDigest+".eml"))
		if readErr != nil {
			return fmt.Errorf("read sealed selected subject: %w", readErr)
		}
		selectedFrom, selectedErr := admission.SelectedSubjectFrom(selected)
		_, allowed := admission.SelectedSubjectAllowed(selectedFrom, subjectAllowlist)
		if selectedErr != nil || !allowed {
			decisionID, idErr := randomID()
			if idErr != nil {
				return idErr
			}
			if err := queue.RecordRejectedCollection(ctx, db, deliveryID, digest, sourceKey, decisionID, "selected_subject_sender_denied", time.Now()); err != nil {
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
		if err := queue.EnqueueCollection(ctx, db, deliveryID, digest, sourceKey, runID, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

func readAllowlist(path string) ([]string, error) {
	if path == "" {
		return []string{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read selected subject allowlist: %w", err)
	}
	values := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			values = append(values, line)
		}
	}
	return values, nil
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
		if err := analyzeRun(ctx, db, claimed, *artifacts, *rspamdEndpoint); err != nil {
			if retryErr := queue.Retry(ctx, db, claimed.ID, "analysis", err.Error(), time.Now().Add(time.Second), 3); retryErr != nil {
				return retryErr
			}
			processed++
			continue
		}
		if err := queue.FinishAnalysis(ctx, db, claimed.ID, owner); err != nil {
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
	reportInput := report.Input{RunID: run.ID, DeliveryID: run.DeliveryID, DeliveredOriginalDigest: digest, AuthContextScope: evidence.LocalIngress, Verdict: verdict, PolicyVersion: "v1", ToolVersions: []string{version}, MissingAnalyzers: verdict.Unavailable, Timeline: []report.TimelineEvent{{Kind: "analysis", Claim: "sealed analysis published"}}}
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
	recipientBytes, err := os.ReadFile(recipientPath)
	if err != nil {
		return "", false, err
	}
	recipient := strings.TrimSpace(string(recipientBytes))
	if recipient == "" {
		return queue.ReplySuppressed, false, nil
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, "runs", run.ID, "report", "manifest.json"))
	if err != nil {
		return "", false, err
	}
	signature, err := os.ReadFile(filepath.Join(root, "runs", run.ID, "report", "manifest.sig"))
	if err != nil {
		return "", false, err
	}
	unknown, err := report.Submit(ctx, smtpAddress, report.Reply{EnvelopeFrom: "", Recipient: recipient, DeliveryID: run.DeliveryID, Manifest: manifestBytes, Signature: signature, ReportText: documents["report.txt"], ReportHTML: documents["report.html"], ReportJSON: documents["report.json"]})
	if err != nil {
		return "", unknown, err
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
