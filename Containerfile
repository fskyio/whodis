FROM golang:1.26-alpine AS builder

RUN apk add --no-cache gcc musl-dev make perl curl

WORKDIR /src/whois
RUN curl -L https://github.com/rfc1036/whois/archive/refs/tags/v5.6.6.tar.gz | tar xz \
    && cd whois-5.6.6 \
    && make whois LDFLAGS="-static" DEFS="-DHAVE_GETOPT_LONG" \
    && mv whois /usr/local/bin/whois

WORKDIR /src/whodis
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o whodis .


FROM scratch

ENV PATH=/usr/local/bin

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /usr/local/bin/whois /usr/local/bin/whois
COPY --from=builder /src/whodis/whodis /usr/local/bin/whodis

EXPOSE 8080
ENTRYPOINT ["whodis"]
