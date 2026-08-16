package intel

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"sort"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/queue"
)

func TestStrongKeysOnlyUseReviewedRules(t *testing.T) {
	values := []Indicator{
		{Type: "attachment_sha256", Value: "attachment"},
		{Type: "risky_landing_domain", Value: "landing.example"},
		{Type: "redirect_domain", Value: "redirect.example"},
		{Type: "selected_from_domain", Value: "sender.example"},
		{Type: "subject_fingerprint", Value: "subject"},
		{Type: "attachment_mime", Value: "weak-mime"},
		{Type: "impersonated_organization", Value: "weak-org"},
	}
	got := strongKeys(values)
	if len(got) != 4 {
		t.Fatalf("strong keys = %#v", got)
	}
	for _, key := range got {
		if key.value == groupingDigest("attachment_mime", "weak-mime") || key.value == groupingDigest("impersonated_organization", "weak-org") {
			t.Fatalf("weak indicator created edge: %#v", key)
		}
	}
}

func TestStrongKeysAcceptSelectedOrSignerOnlyWithSubject(t *testing.T) {
	tests := []struct {
		name   string
		values []Indicator
		want   []string
	}{
		{"selected", []Indicator{{Type: "selected_from_domain", Value: "from.example"}, {Type: "subject_fingerprint", Value: "subject"}}, []string{groupingDigest("sender-domain", "from.example") + ":" + groupingDigest("subject-fingerprint", "subject")}},
		{"signer", []Indicator{{Type: "dkim_domain", Value: "signer.example"}, {Type: "subject_fingerprint", Value: "subject"}}, []string{groupingDigest("sender-domain", "signer.example") + ":" + groupingDigest("subject-fingerprint", "subject")}},
		{"both", []Indicator{{Type: "selected_from_domain", Value: "from.example"}, {Type: "dkim_domain", Value: "signer.example"}, {Type: "subject_fingerprint", Value: "subject"}}, []string{groupingDigest("sender-domain", "from.example") + ":" + groupingDigest("subject-fingerprint", "subject"), groupingDigest("sender-domain", "signer.example") + ":" + groupingDigest("subject-fingerprint", "subject")}},
		{"neither", []Indicator{{Type: "selected_from_domain", Value: "from.example"}, {Type: "dkim_domain", Value: "signer.example"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strongKeys(tt.values)
			sort.Strings(tt.want)
			if len(got) != len(tt.want) {
				t.Fatalf("keys=%#v", got)
			}
			for i := range got {
				if got[i].rule != "sender-subject" || got[i].value != tt.want[i] {
					t.Fatalf("keys=%#v want=%#v", got, tt.want)
				}
			}
		})
	}
}

func TestStrongKeysGroupLandingAndRedirectByCanonicalDomain(t *testing.T) {
	keys := strongKeys([]Indicator{
		{Type: "risky_landing_domain", Value: "shared.example", Digest: "type-specific-landing"},
		{Type: "redirect_domain", Value: "shared.example", Digest: "type-specific-redirect"},
	})
	if len(keys) != 1 || keys[0].rule != "risky-domain" || keys[0].value != groupingDigest("risky-domain", "shared.example") {
		t.Fatalf("strong keys = %#v", keys)
	}
}

func TestProjectOnceClosesClaimRowsBeforeStateWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	db, err := queue.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedCampaignRun(t, ctx, db, "run-invalid-path", 100)
	if _, err := db.ExecContext(ctx, `INSERT INTO intel_projection_outbox(run_id,manifest_path,manifest_digest,created_at) VALUES(?,?,?,?)`, "run-invalid-path", "not/a/bundle", "digest", 100); err != nil {
		t.Fatal(err)
	}
	projector := Projector{
		DB:          db,
		Artifacts:   t.TempDir(),
		Trusted:     []ed25519.PublicKey{make(ed25519.PublicKey, ed25519.PublicKeySize)},
		CampaignKey: []byte("01234567890123456789012345678901"),
	}
	n, err := projector.ProjectOnce(ctx, "worker", 1)
	if err != nil || n != 1 {
		t.Fatalf("ProjectOnce() = %d, %v", n, err)
	}
	var state, reason string
	if err := db.QueryRowContext(ctx, `SELECT state,reason_code FROM intel_projection_outbox WHERE run_id=?`, "run-invalid-path").Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "terminal" || reason != "invalid_manifest_path" {
		t.Fatalf("outbox state = %q, reason = %q", state, reason)
	}
}

func TestRebuildComponentsKeepsSingletonsAndSupersession(t *testing.T) {
	ctx := context.Background()
	db, err := queue.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i, run := range []string{"run-a", "run-b", "run-bridge", "run-singleton"} {
		seedCampaignRun(t, ctx, db, run, int64(100+i))
	}
	version := PolicyVersion
	for _, run := range []string{"run-a", "run-b", "run-singleton"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO intel_projected_runs(projection_version,run_id,projected_at) VALUES(?,?,?)`, version, run, 100); err != nil {
			t.Fatal(err)
		}
	}
	for run, key := range map[string]string{"run-a": "rule:a", "run-b": "rule:b"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO run_grouping_edges(projection_version,run_id,strong_grouping_key,rule_id,created_at) VALUES(?,?,?,?,?)`, version, run, key, "test", 100); err != nil {
			t.Fatal(err)
		}
	}
	p := Projector{DB: db, CampaignKey: []byte("01234567890123456789012345678901"), Now: func() time.Time { return time.Unix(200, 0) }}
	if err := p.RebuildComponents(ctx); err != nil {
		t.Fatal(err)
	}
	var beforeB string
	if err := db.QueryRowContext(ctx, `SELECT campaign_id FROM campaign_members WHERE projection_version=? AND run_id='run-b'`, version).Scan(&beforeB); err != nil {
		t.Fatal(err)
	}
	var members int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM campaign_members WHERE projection_version=? AND campaign_id IN (SELECT campaign_id FROM campaign_members WHERE projection_version=? AND run_id='run-singleton')`, version, version).Scan(&members); err != nil || members != 1 {
		t.Fatalf("singleton members = %d, %v", members, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO intel_projected_runs(projection_version,run_id,projected_at) VALUES(?,?,?)`, version, "run-bridge", 100); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rule:a", "rule:b"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO run_grouping_edges(projection_version,run_id,strong_grouping_key,rule_id,created_at) VALUES(?,?,?,?,?)`, version, "run-bridge", key, "test", 100); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.RebuildComponents(ctx); err != nil {
		t.Fatal(err)
	}
	var supersededBy string
	if err := db.QueryRowContext(ctx, `SELECT superseded_by FROM campaign_projections WHERE projection_version=? AND campaign_id=?`, version, beforeB).Scan(&supersededBy); err != nil || supersededBy == "" {
		t.Fatalf("late merge did not retain supersession: %q, %v", supersededBy, err)
	}
}

func seedCampaignRun(t *testing.T, ctx context.Context, db *sql.DB, run string, occurredAt int64) {
	t.Helper()
	delivery := "delivery-" + run
	if _, err := db.ExecContext(ctx, `INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES(?,?,?,?)`, delivery, "digest-"+run, "source-"+run, occurredAt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES(?,?,?,?)`, run, delivery, "complete", occurredAt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO result_records(run_id,delivery_id,occurred_at,verdict,policy_version,schema_version,auth_scope,selected_subject_status,unavailable_analyzers,risk_summary,category_summary,manifest_digest,manifest_path,source_artifact_digests,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, run, delivery, occurredAt, "FAILED", "p", "s", "scope", "selected", 0, "risk", "category", "manifest", "runs/"+run+"/report/manifest.json", "source", occurredAt); err != nil {
		t.Fatal(err)
	}
}
