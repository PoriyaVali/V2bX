# V2bX's DNS forwarder

Every core resolves the names its users connect to. By default that means the
machine's resolvers, over UDP. On a path that loses UDP packets — one server
measured 26 of 200 DNS queries unanswered over UDP while all 200 were answered
over TCP — each lost query is a connection that waits out a resolver timeout:
pages hang for seconds, and the node looks slow whatever the protocol.

V2bX runs a small DNS forwarder of its own so that no core depends on that.

## What it does

- It asks the resolvers of `/etc/resolv.conf` (behind systemd-resolved's stub,
  the resolvers resolved itself uses).
- A query goes over UDP. If the answer is late, the same query is sent over
  TCP as well and the first answer wins, so a lost packet costs a fraction of
  a second and not a timeout.
- It counts the UDP queries that go unanswered. At 5 % of the last 50 it asks
  that resolver over TCP first, on connections it keeps open, and logs:
  `UDP DNS queries to this resolver go unanswered: asking it over TCP until
  they are answered again`.
- While on TCP it still tries UDP with one query in ten. After 50 of those in
  a row are answered it returns to UDP and logs that too.
- Answers are kept for as long as their records allow (an hour at most, five
  minutes for a name that does not exist).
- A resolver that fails is followed by the next; one that answers nothing at
  all is asked last.

## Which cores use it

| Core | How |
|------|-----|
| xray, hysteria2, mihomo, mdns | Go's resolver, which the process points at the forwarder |
| sing | its DNS server, where the config names none or the machine's own (`"address": "local"`, as the installed `sing_origin.json` does) |
| xray's own DNS module | the forwarder, unless `DnsConfigPath` is set |
| trusttunnel | The endpoint is a separate program that resolves with the C library. While the forwarder is on TCP when the endpoint starts, it is started with `RES_OPTIONS=use-vc`, which makes glibc ask over TCP too |

The panel client and certificate issuance resolve through it as well.

A DNS server you chose yourself — in `sing_origin.json`, Xray's `dns.json`,
the Hysteria2 `Resolver` — is used as before.

## Port 53 is left alone

The forwarder listens on `127.0.0.1` on a port the system picks, for this
process only. It does not touch `/etc/resolv.conf` and never binds port 53, so
it cannot collide with an mdns (DNS-tunnel) node, which needs UDP 53 on the
public address, or with a resolver installed on the machine.

If you installed a local resolver (Unbound, dnsmasq) to work around lossy UDP
and want to run an mdns node on the same machine, make sure that resolver
listens on `127.0.0.1` only and the mdns node's `ListenIP` is the public
address: two programs cannot both hold `0.0.0.0:53`.

## When it does not start

- `resolv.conf` names a resolver on this machine other than systemd-resolved's
  stub (Unbound, dnsmasq, Docker's `127.0.0.11`). What that one forwards to is
  its own business; V2bX leaves it alone. Set `Servers` to use the forwarder
  anyway.
- `Mode` is `system`.

The log says which at startup. Nothing else changes in either case.

## Configuration

Nothing is needed. To change the behaviour, in `config.json`:

```json
{
  "DNS": {
    "Mode": "auto",
    "Servers": ["1.1.1.1", "9.9.9.9"]
  }
}
```

- `Mode`: `auto` (default), `tcp` (always TCP), or `system` (no forwarder:
  every core resolves as it did before).
- `Servers`: resolvers to ask instead of the machine's. IP addresses, with or
  without a port.

It applies when V2bX starts.

## What it does not fix

- UDP that users send through the node (QUIC, games, calls) rides the same
  lossy path. Only the node's own DNS queries move to TCP.
- A Docker container on a bridge network sees Docker's resolver at
  `127.0.0.11`; set `Servers` there.
