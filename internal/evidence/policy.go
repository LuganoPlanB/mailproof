package evidence

import "sort"

// Decide is deliberately categorical: no score or absent symbol can become a pass.
func Decide(scope AuthScope, evidence []Evidence, contradictions []Contradiction) Verdict {
	v := Verdict{Category: Indeterminate, Technical: "indeterminate", Behavior: "indeterminate", Support: []string{}, Contradictions: []string{}, Unavailable: []string{}, Rules: []string{}}
	authenticated, malicious, suspicious, complete := false, false, false, true
	for _, e := range evidence {
		switch e.Status {
		case Failed, Unavailable, Skipped, Unknown:
			complete = false
			v.Unavailable = append(v.Unavailable, e.ID)
		}
		if e.Category == "authentication" && e.Status == Observed && (e.Authority == Authoritative || e.Authority == Strong) {
			authenticated = true
		}
		if (e.Category == "malware" || e.Category == "yara" || e.Category == "threat_feed") && e.Status == Observed && e.Authority == Authoritative {
			malicious = true
			v.Support = append(v.Support, e.ID)
		}
		if e.Category == "behavior" && e.Status == Observed {
			suspicious = true
			v.Support = append(v.Support, e.ID)
		}
	}
	material := false
	for _, c := range contradictions {
		if c.Material {
			material = true
			v.Contradictions = append(v.Contradictions, c.ID)
		}
	}
	if malicious {
		v.Category = KnownMalicious
		v.Behavior = "known_malicious"
		v.Rules = append(v.Rules, "authoritative-malware")
	} else if authenticated && suspicious {
		v.Category = AuthenticatedButSuspicious
		v.Technical = "authenticated"
		v.Behavior = "suspicious"
		v.Rules = append(v.Rules, "authenticated-suspicious")
	} else if authenticated && complete && !material {
		v.Category = Verified
		v.Technical = "authenticated"
		v.Behavior = "no_material_signal"
		v.Rules = append(v.Rules, "complete-authentication")
	} else if suspicious || material {
		v.Category = Suspicious
		v.Behavior = "suspicious"
		v.Rules = append(v.Rules, "suspicion-or-contradiction")
	}
	if scope == Detached && !authenticated && v.Category == Verified {
		v.Category = Indeterminate
	}
	sort.Strings(v.Support)
	sort.Strings(v.Contradictions)
	sort.Strings(v.Unavailable)
	sort.Strings(v.Rules)
	return v
}
