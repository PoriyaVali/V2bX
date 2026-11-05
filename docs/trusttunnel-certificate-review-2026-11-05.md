# TrustTunnel core review — 2026-11-05

A review of how V2bX's TrustTunnel core gets, renews and delivers its
certificate, and how it performs, with endpoint v1.1.0-dm.1 and, for comparison,
v1.0.41-dm.3. The October audits ([2026-10-23](trusttunnel-certificate-audit-2026-10-23.md),
[2026-10-24](certificate-lifecycle-audit-2026-10-24.md)) tested the lifecycle with
fake certificate operations only, and listed real issuance and renewal as
untested. This time both ran for real.

## How it was tested

`scripts/e2e/trusttunnel-acme/run.sh` starts two local Pebble v2.10.0 CAs, one
issuing 31-day certificates and one issuing 29-day certificates, and a mock DNS
that resolves every name to 127.0.0.1. The `acme_e2e` tests in
`core/trusttunnel/acme_e2e_test.go` then run V2bX's real certificate manager:
lego, HTTP-01 answered on port 80, the real `setup_wizard` and
`trusttunnel_endpoint`. They check what a subscriber's client would see: a TLS
handshake whose chain verifies against the CA's root, over TCP and over QUIC.
Only an `acme_e2e` build can point ACME away from Let's Encrypt, and no release
uses that tag.

| Scenario | Result (both endpoint versions) |
| --- | --- |
| Issuance at AddNode | Issued and served in about 6 s. TCP and QUIC serve the same verified chain. |
| 31 days left | Not renewed: the same serial after three maintenance polls. |
| 29 days left | Renewed at the first check. TCP and QUIC serve the new certificate. Same endpoint PID, nothing logged at error level. |
| Port 80 held by a web server, `HTTPWebRoot` set | Issued through the web root. |
| Reload to a new hostname | Issued in about 5 s while the old endpoint answered 51 of 51 probes. The new name was served 139 ms after the old endpoint was retired. |
| Same, CA unreachable | Preparation fails at once and the old endpoint keeps serving. |

Delivery to QUIC was also confirmed in the endpoint source. The QUIC listener
builds its TLS configuration for each new connection, and selects the
certificate at handshake time from the same table that SIGHUP replaces.

## Bugs found and fixed

1. **A reload issued the certificate after retiring the endpoint.** The
   controller prepares certificates before retiring a node, but TrustTunnel
   issues its own certificate inside AddNode, which runs after the old endpoint
   is gone. A new hostname, email or certificate type left the node down for
   the whole issuance, and down until the next successful poll when issuance
   failed. A new optional interface, `core.NodePreparer`, lets the controller
   have TrustTunnel issue the certificate first, while the old endpoint still
   serves. AddNode then finds it in place. Tests:
   `TestReload_PreparesBeforeRetiringAndKeepsTheOldNodeOnFailure`,
   `TestPrepareNode*`, `TestSelectorPrepareNode_*` and the real-ACME reload
   test.
2. **Let's Encrypt could only use the built-in HTTP-01 server.** With port 80
   taken, issuance and renewal always failed. The error even advised
   `CertMode dns` or `HTTPWebRoot`, settings this core ignored. The node's
   `CertConfig` now chooses the challenge, and nothing else: name, account and
   files stay the panel's and V2bX's. Switching challenge does not re-issue.
   Tests: `TestLetsEncryptTakesOnlyTheChallengeFromTheNodeConfig` and the
   real-ACME web-root test.
3. **Every successful renewal was logged as a failure.** The renewed pair was
   validated against the clock read before the renewal began. A certificate
   that starts at issuance, such as Pebble's, was rejected as "outside its
   validity period" at error level, and published one poll later. Let's
   Encrypt backdates by an hour, which hid this in production, but it would show
   for any certificate starting less than one renewal's duration before the
   check. Test: `TestRenewedCertificateIsJudgedByTheClockAfterTheRenewal`.
4. **Readiness was given up after 30 seconds.** An endpoint whose metrics port
   answered later was never marked ready, so it was never sent SIGHUP. Every
   user change after that, removing a user included, waited for the endpoint's
   next restart. Readiness is now polled every 5 seconds after the first 30.
   Test: `TestReadinessIsPolledPastTheFastWindow`.

The unit tests for 1, 3 and 4 were run against the code before the fix, and all
three failed as described.

## Performance

The same harness, one user, a 256 MiB echo through an authenticated HTTP/2
CONNECT tunnel, six alternated runs per endpoint on one machine:

| Metric | v1.0.41-dm.3 | v1.1.0-dm.1 | p |
| --- | --- | --- | --- |
| Throughput | 190 MiB/s | 202 MiB/s | 0.11 |
| Endpoint CPU per MiB | 5.9 ms | 5.6 ms | 0.19 |
| Idle CPU over 10 s | 0 | 0 | — |
| Idle RSS | 5.7 MB | 6.0 MB | 0.002 |
| Billed to the user | exactly 256/256 MiB, every run | exactly 256/256 MiB, every run | — |

No regression. The only significant change is 0.3 MB more idle memory per node.
On the V2bX side, one steady-state certificate poll costs about 0.26 ms of CPU
and 34 KB of allocation. At once every 5 seconds, that is roughly 0.005% of a
core per node.

## Not covered

- DNS-01 was not issued for real: the mock DNS cannot take lego's propagation
  check. Its configuration path is unit-tested, and the DNS-01 code itself is
  the shared certificate manager's, which the other cores use.
- Let's Encrypt production was not contacted.
- Renewal uses the fixed 30-day window. That is safe for Let's Encrypt's
  announced lifetimes: 90 days now, 64 from February 2027, 45 from February
  2028. ACME Renewal Information (renewing early when the CA asks, for example
  after a revocation event) is not implemented.
- QUIC throughput was not measured; only certificate delivery over QUIC was
  tested.
