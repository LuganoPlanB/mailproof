# ADR 0003: v1 capability boundary

## Status

Accepted for the v1 Compose spine.

## Capability matrix

| Capability | Status | Owner |
| --- | --- | --- |
| Postfix/Dovecot ingress | required | `mail-ingress` |
| Async Rspamd `/checkv3` (auth, phishing, MIME/archive, ClamAV, olefy) and Lua projection | required | `mail-ingress-rspamd` |
| Independent Unbound DNS/SPF/DMARC observations | required | `analysis-adapters-dns-auth` |
| RFC822/MIME projection | required | `evidence-engine-mail-projection` |
| Deterministic policy and signed reports/safe replies | required | `evidence-engine-policy`, `reporting` |
| URL/IDNA/SSRF-safe redirect enrichment of Rspamd URLs | required | `analysis-adapters-url` |
| YARA, deep archive, PDF, LNK, QR and English semantic rules | required | `analysis-adapters-supplementary`, `semantic-analysis` |
| S/MIME and OpenPGP with mounted operator trust material | configured | `analysis-adapters-crypto` |
| Licensed threat-feed adapters | configured | `analysis-adapters-threat-feeds` |
| SMTP-time Rspamd milter actions, IMAP/WebUI, provider LLM | deferred | none in v1 |
| Independent DKIM/ARC, statistical learning, multi-host queues, object storage | deferred | none in v1 |
| General-purpose Rspamd-to-Go callback plugin | deferred | none in v1 |

Rspamd is primary only for its owned scan observations. Unbound-backed DNS/SPF/
DMARC, URL enrichment, and supplementary tools are independent or supplementary
evidence and retain that provenance. S/MIME/OpenPGP without mounted trust
material and unconfigured feeds report `UNAVAILABLE`; they do not silently pass.

No later milestone may implement a deferred capability without an explicit v2
decision. The table has one owner per capability and makes required,
configured, and deferred behavior reviewable.
