FROM golang:1.26-alpine AS builder

WORKDIR /src/whodis
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o whodis .


FROM scratch

COPY --from=builder /src/whodis/whodis /usr/local/bin/whodis

EXPOSE 8080
ENTRYPOINT ["whodis"]
