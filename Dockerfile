# Build stage
FROM golang:1.25.11-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN GOEXPERIMENT=jsonv2 go mod tidy
RUN GOEXPERIMENT=jsonv2 go build -v -o V2bX -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor mdns trusttunnel" -trimpath -ldflags "-s -w -buildid="

# Release stage
FROM alpine
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime \
    && echo "Asia/Tehran" > /etc/timezone
RUN mkdir -p /etc/V2bX/
COPY --from=builder /app/V2bX /usr/local/bin/V2bX
ENTRYPOINT ["V2bX", "server", "-c", "/etc/V2bX/config.json"]
