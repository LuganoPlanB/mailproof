package intel

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/queue"
)

func TestStrongKeysOnlyUseReviewedRules(t *testing.T) {
	values := []Indicator{
		{Type: "attachment_sha256", Digest: "attachment"},
		{Type: "risky_landing_domain", Digest: "landing"},
		{Type: "redirect_domain", Digest: "redirect"},
		{Type: "selected_from_domain", Digest: "sender"},
		{Type: "subject_fingerprint", Digest: "subject"},
		{Type: "attachment_mime", Digest: "weak-mime"},
		{Type: "impersonated_organization", Digest: "weak-org"},
	}
	got := strongKeys(values)
	if len(got) != 4 {
		t.Fatalf("strong keys = %#v", got)
	}
	for _, key := range got {
		if key.value == "weak-mime" || key.value == "weak-org" {
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
		{"selected", []Indicator{{Type: "selected_from_domain", Digest: "from"}, {Type: "subject_fingerprint", Digest: "subject"}}, []string{"from:subject"}},
		{"signer", []Indicator{{Type: "dkim_domain", Digest: "signer"}, {Type: "subject_fingerprint", Digest: "subject"}}, []string{"signer:subject"}},
		{"both", []Indicator{{Type: "selected_from_domain", Digest: "from"}, {Type: "dkim_domain", Digest: "signer"}, {Type: "subject_fingerprint", Digest: "subject"}}, []string{"from:subject", "signer:subject"}},
		{"neither", []Indicator{{Type: "selected_from_domain", Digest: "from"}, {Type: "dkim_domain", Digest: "signer"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strongKeys(tt.values)
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
