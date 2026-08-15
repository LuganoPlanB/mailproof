# Container boundary model

Postfix is the only service with a host-published port. `public` is used only
for SMTP ingress and the smoke fixture; `mail` carries Postfix-to-Dovecot LMTP
and collector access; `analyzer` carries worker, Rspamd, Redis, and Unbound;
`scanner` is limited to Rspamd, ClamAV, and olefy; `report` is limited to the
reporter and Postfix submission listener. All but `public` are Docker internal
networks. No container has a fixed name.

The collector alone reads Maildir and restricted ingress logs and writes sealed
message/delivery artifacts. Workers mount those inputs read-only and receive
only the shared SQLite/run publication state. The reporter receives completed
artifacts read-only, writes through a separate report volume, and is the only
service with the signing key. Rspamd configuration and `mailproof.lua` are
read-only binds.

Services use no-new-privileges, capability removal, read-only roots where the
underlying daemon permits it, bounded tmpfs and PID/resource limits. The
ClamAV daemon is the sole exception to an empty capability set: it needs
`CHOWN`, `SETGID`, and `SETUID` to initialize its package-owned log and drop
from its package bootstrap identity to `clamav`;
Rspamd has the same narrowly-scoped bootstrap exception for its `_rspamd`
runtime identity; its only scanner route is the private `scanner` network.
the service has no route outside `scanner`.
remaining single-host risk is intentional: a compromised worker can corrupt
its shared run and SQLite publication state. It cannot alter Maildir, sealed
messages/deliveries, the token registry, or signing key. Immutable publication,
digest checks, report signing, and offline backups are compensating controls.

The scanner containers have no public, report, or worker route; they parse
hostile material only inside their own temporary filesystems. Lua adds no
network capability beyond the Rspamd process. Scanner, image, SBOM, license,
and vulnerability exceptions must be recorded in `config/security-exceptions.yml`
with owner, expiry, rationale, and compensating controls.
