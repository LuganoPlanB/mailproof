# Ingress transaction context v1

The collector trusts only the first `Received:` field when it names `postfix.mailproof.test` and includes a Postfix queue ID. It correlates that ID with exactly one restricted Postfix log record in a five-minute receipt window. Required fields are queue ID, peer IP/name, HELO, protocol, envelope sender (including a distinct null sender), recipient, SASL user, and TLS state. Zero or multiple candidates produce `lost_coverage`; lower Received, Return-Path, and Authentication-Results fields are untrusted mail content.

The schema is `mailproof.ingress-context/v1`; JSON construction and persistence belong to the later collector milestone.
