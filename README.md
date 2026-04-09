# whodis

A lightweight, self-hosted WHOIS lookup tool with a clean web interface. Query domain names, TLDs, IP addresses, CIDR ranges, and ASNs from your browser.

## Deploying

### Container (recommended)

```sh
docker run -p 8080:8080 foundry.fsky.io/fsky/whodis:latest
```

A [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html) unit file is available at [`contrib/quadlet/whodis.container`](contrib/quadlet/whodis.container) for deploying with Podman and systemd.

### From source

Requires Go 1.26+ and the [rfc1036/whois](https://github.com/rfc1036/whois) binary available on your system.

```sh
go build
./whodis
```

Then open http://localhost:8080 in your browser.

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

The code of this project is released under the [Unlicense](https://unlicense.org/). See the `LICENSE` file for details.
