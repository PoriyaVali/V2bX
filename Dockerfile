# Build stage
# Same Go as the release build. This was 1.25.11 while go.mod asks for 1.26,
# so every image build since v1.4 stopped at the first go command.
FROM golang:1.27.1-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0
# Download, not tidy: tidy rewrites go.mod inside the image, so the image was
# not built from the dependency set the release was. The local modules go.mod
# replaces (third_party/) belong to that set; without them, download stopped
# at the first replacement, and no image could be built from v1.7.5 on.
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download
COPY . .
RUN GOEXPERIMENT=jsonv2 go build -v -o V2bX -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor mdns trusttunnel" -trimpath -ldflags "-s -w -buildid="

# Release stage
FROM alpine
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime \
    && echo "Asia/Tehran" > /etc/timezone
RUN mkdir -p /etc/V2bX/
COPY --from=builder /app/V2bX /usr/local/bin/V2bX
ENTRYPOINT ["V2bX", "server", "-c", "/etc/V2bX/config.json"]
