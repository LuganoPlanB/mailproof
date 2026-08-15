package intel

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"time"

	"github.com/luganoplanb/mailproof/internal/report"
)

// PolicyVersion defines the reviewed strong-edge rules. Changing it is a
// parallel projection, never a silent reclassification of active campaigns.
const PolicyVersion = "campaign-components/v1"

// Projector reads only the signed report bundle mounted read-only. Its state
// database contains safe projections, never source mail or raw report content.
type Projector struct {
	DB            *sql.DB
	Artifacts     string
	Trusted       []ed25519.PublicKey
	CampaignKey   []byte
	PolicyVersion string
	Now           func() time.Time
}

// ProjectOnce leases at most batch rows. Invalid/tampered evidence is terminal
// and reason-coded; transient database faults leave the row retryable.
func (p Projector) ProjectOnce(ctx context.Context, owner string, batch int) (int, error) {
	if p.DB == nil || p.Artifacts == "" || len(p.Trusted) == 0 || len(p.CampaignKey) < 32 || batch < 1 || batch > 25 {
		return 0, errors.New("invalid intel projector configuration")
	}
	if p.PolicyVersion == "" {
		p.PolicyVersion = PolicyVersion
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	rows, err := p.DB.QueryContext(ctx, `UPDATE intel_projection_outbox SET state='leased',lease_owner=?,lease_until=?,attempts=attempts+1 WHERE run_id IN (SELECT run_id FROM intel_projection_outbox WHERE (state='pending' OR (state='retryable' AND not_before<=?) OR (state='leased' AND lease_until<?)) ORDER BY created_at LIMIT ?) RETURNING run_id,manifest_path,manifest_digest`, owner, now.Add(30*time.Second).Unix(), now.Unix(), now.Unix(), batch)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var run, path, manifestDigest string
		if err := rows.Scan(&run, &path, &manifestDigest); err != nil {
			return n, err
		}
		n++
		// Database paths are trusted only after they meet the immutable bundle layout.
		bundle, ok := safeBundlePath(p.Artifacts, path, run)
		if !ok {
			_ = p.finish(ctx, run, "terminal", "invalid_manifest_path", now)
			continue
		}
		evidence, err := ReadVerifiedCampaignEvidence(bundle, manifestDigest, p.Trusted)
		if err != nil {
			_ = p.finish(ctx, run, "terminal", "unverified_evidence", now)
			continue
		}
		if err := p.persist(ctx, run, evidence, now); err != nil {
			_ = p.finish(ctx, run, "retryable", "projection_failed", now)
			continue
		}
		_ = p.finish(ctx, run, "complete", "", now)
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	if n > 0 {
		if err := p.RebuildComponents(ctx); err != nil {
			return n, err
		}
	}
	return n, nil
}

func safeBundlePath(root, manifestPath, run string) (string, bool) {
	want := filepath.Join("runs", run, "report", "manifest.json")
	if filepath.Clean(manifestPath) != want {
		return "", false
	}
	return filepath.Join(root, "runs", run, "report"), true
}
func (p Projector) finish(ctx context.Context, run, state, reason string, now time.Time) error {
	_, e := p.DB.ExecContext(ctx, `UPDATE intel_projection_outbox SET state=?,reason_code=?,lease_owner='',lease_until=0,completed_at=CASE WHEN ?='complete' OR ?='terminal' THEN ? ELSE NULL END WHERE run_id=?`, state, reason, state, state, now.Unix(), run)
	return e
}

func (p Projector) persist(ctx context.Context, run string, envelope report.CampaignEvidence, now time.Time) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	version := p.PolicyVersion
	if version == "" {
		version = PolicyVersion
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, indicator := range IndicatorsFromVerifiedEnvelope(envelope).Indicators {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO run_indicators(projection_version,run_id,indicator_type,indicator_value,indicator_digest,key_id,normalization_version,source_artifact_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, version, run, indicator.Type, indicator.Value, indicator.Digest, indicator.KeyID, indicator.Version, indicator.SourceArtifactDigest, now.Unix()); err != nil {
			return err
		}
	}
	// A verified eligible run is materialized even when it has no strong (or no
	// displayable) indicators, so the component model can expose its explicit
	// singleton rather than silently dropping it from the projection.
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO intel_projected_runs(projection_version,run_id,projected_at) VALUES(?,?,?)`, version, run, now.Unix()); err != nil {
		return err
	}
	// Strong rules alone connect components. MIME, organization, ASN, mismatch and
	// extension values remain filter/display metadata and can never create edges.
	for _, key := range strongKeys(IndicatorsFromVerifiedEnvelope(envelope).Indicators) {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO run_grouping_edges(projection_version,run_id,strong_grouping_key,rule_id,created_at) VALUES(?,?,?,?,?)`, version, run, key.value, key.rule, now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type groupingKey struct{ rule, value string }

func strongKeys(values []Indicator) []groupingKey {
	var out []groupingKey
	domains, subjects := map[string]bool{}, map[string]bool{}
	for _, v := range values {
		switch v.Type {
		case "attachment_sha256":
			out = append(out, groupingKey{"attachment-sha256", v.Digest})
		case "risky_landing_domain", "redirect_domain":
			out = append(out, groupingKey{"risky-domain", v.Digest})
		case "selected_from_domain":
			domains[v.Digest] = true
		case "dkim_domain":
			domains[v.Digest] = true
		case "subject_fingerprint":
			subjects[v.Digest] = true
		}
	}
	// Each selected From or DKIM signer domain independently forms a strong key
	// only with a keyed subject fingerprint. A shared domain is deduplicated and
	// sorted so the both-present case is deterministic.
	for domain := range domains {
		for subject := range subjects {
			if domain != "" && subject != "" {
				out = append(out, groupingKey{"sender-subject", domain + ":" + subject})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rule+"\x00"+out[i].value < out[j].rule+"\x00"+out[j].value })
	return out
}

// RebuildComponents deterministically walks the bipartite run/key graph. Weak
// values are absent from that graph, so they cannot accidentally cluster runs.
func (p Projector) RebuildComponents(ctx context.Context) error {
	version := p.PolicyVersion
	if version == "" {
		version = PolicyVersion
	}
	rows, err := p.DB.QueryContext(ctx, `SELECT run_id FROM intel_projected_runs WHERE projection_version=? ORDER BY run_id`, version)
	if err != nil {
		return err
	}
	runKeys, keyRuns := map[string][]string{}, map[string][]string{}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return err
		}
		runKeys[r] = nil
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = p.DB.QueryContext(ctx, `SELECT run_id,strong_grouping_key FROM run_grouping_edges WHERE projection_version=? ORDER BY run_id,strong_grouping_key`, version)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r, k string
		if err := rows.Scan(&r, &k); err != nil {
			return err
		}
		runKeys[r] = append(runKeys[r], k)
		keyRuns[k] = append(keyRuns[k], r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE campaign_projections SET active=0 WHERE projection_version=? AND active=1`, version); err != nil {
		return err
	}
	seen := map[string]bool{}
	now := time.Now().UTC().Unix()
	for start := range runKeys {
		if seen[start] {
			continue
		}
		queue := []string{start}
		seen[start] = true
		var runs, keys []string
		seenKey := map[string]bool{}
		for len(queue) > 0 {
			r := queue[0]
			queue = queue[1:]
			runs = append(runs, r)
			for _, k := range runKeys[r] {
				if !seenKey[k] {
					seenKey[k] = true
					keys = append(keys, k)
					for _, next := range keyRuns[k] {
						if !seen[next] {
							seen[next] = true
							queue = append(queue, next)
						}
					}
				}
			}
		}
		sort.Strings(runs)
		sort.Strings(keys)
		component := "singleton:" + runs[0]
		if len(keys) > 0 {
			component = keys[0]
		}
		id := campaignID(p.CampaignKey, version, component)
		first, last := now, now
		for _, run := range runs {
			var at int64
			if err := tx.QueryRowContext(ctx, `SELECT occurred_at FROM result_records WHERE run_id=?`, run).Scan(&at); err != nil {
				return err
			}
			if at < first {
				first = at
			}
			if at > last {
				last = at
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO campaign_members(projection_version,campaign_id,run_id,occurred_at) VALUES(?,?,?,?)`, version, id, run, at); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO campaign_projections(projection_version,campaign_id,component_key,active,superseded_by,first_seen,last_seen,hit_count,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(projection_version,campaign_id) DO UPDATE SET component_key=excluded.component_key,active=1,superseded_by='',first_seen=excluded.first_seen,last_seen=excluded.last_seen,hit_count=excluded.hit_count`, version, id, component, 1, "", first, last, len(runs), now); err != nil {
			return err
		}
		for _, run := range runs {
			if _, err := tx.ExecContext(ctx, `UPDATE campaign_projections SET superseded_by=? WHERE projection_version=? AND campaign_id IN (SELECT campaign_id FROM campaign_members WHERE projection_version=? AND run_id=?) AND campaign_id<>? AND active=0 AND superseded_by=''`, id, version, version, run, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func campaignID(key []byte, version, component string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(version + "\x00" + component))
	return hex.EncodeToString(m.Sum(nil)[:16])
}
