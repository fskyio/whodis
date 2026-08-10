# who dis?

A lightweight, self-hosted WHOIS lookup tool with a clean web interface. Query domain names, TLDs, IP addresses, CIDR ranges, and ASNs from your browser.

![Screenshot of who dis?](./docs/images/screenshot.png)

## Deploying

### Container (recommended)

```sh
docker run -p 8080:8080 foundry.fsky.io/fsky/whodis:latest
```

A [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) unit file is available at [`contrib/quadlet/whodis.container`](contrib/quadlet/whodis.container) for deploying with Podman and systemd.

### From source

Requires Go 1.26+.

```sh
go build
./whodis
```

Then open http://localhost:8080 in your browser.

## Go package

The native client is also importable without pulling the web application into
your program:

```go
import "foundry.fsky.io/fsky/whodis/whois"

client := whois.NewClient()
result, err := client.Lookup(ctx, "example.com")
```

The repository remains one Go module, so its downloaded source archive also
contains the web app, but importing `whois` neither compiles nor initializes
the application package.

`Lookup` chooses an appropriate server and follows recognized referrals.
`Query` sends an exact, single-line query to a caller-selected `whois.Endpoint`.
Responses are returned as raw bytes together with the endpoint, exact wire
query, and referral metadata; interpreting registry records is left to the
caller.

When a later referral fails, `Lookup` returns the completed responses together
with the error. Errors support `errors.Is` and `errors.As`, including typed
operation errors and registry web URLs for resources without WHOIS service.

Automatic lookups only contact public WHOIS/RWhois endpoints by default.
Direct queries permit caller-selected private endpoints, and both policies can
be replaced with client options.

The routing snapshot is compiled into the package. Maintainers can refresh it
from the public IANA registries with:

```sh
go generate ./whois
```

## Configuration

Configuration is handled through environment variables:

| Variable                | Default | Description                                                                 |
| ----------------------- | ------- | --------------------------------------------------------------------------- |
| `PORT`                  | `8080`  | TCP port the HTTP server listens on                                         |
| `CACHE_TTL`             | `24h`   | Cache duration for successful lookups. Accepts Go duration strings (`1h`, `30m`, etc.) |
| `RATE_LIMIT_PER_MINUTE` | `20`    | Per-IP rate limit applied only to cache misses. Set to `0` to disable.      |
| `RATE_LIMIT_BURST`      | `10`    | Maximum burst of cache-miss lookups a single IP can make before throttling. |
| `TRUST_PROXY_HEADERS`   | `false` | When `true`, honor `X-Forwarded-For` / `X-Real-IP` for client IP. Only enable when whodis is behind a trusted reverse proxy. |

Error results are cached for 5 minutes regardless of `CACHE_TTL`. Rate limiting only applies to cache misses. Popular lookups served from cache are never throttled.

## License

The code of this project is released under the [Zero-Clause BSD License](https://opensource.org/license/0bsd/). See the `LICENSE` file for details.
