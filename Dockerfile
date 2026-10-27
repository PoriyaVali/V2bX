# Compile on the build host and cross-compile the static binary for the image.
# Emulating the Go compiler made the arm64 image validation unnecessarily slow.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0
ARG VERSION=TempVersion
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache git python3
# Download, not tidy: tidy rewrites go.mod inside the image, so the image was
# not built from the dependency set the release was. The local modules go.mod
# replaces (third_party/) belong to that set; without them, download stopped
# at the first replacement, and no image could be built from v1.7.5 on.
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download
COPY . .
RUN python3 scripts/prepare_tls_dependencies.py --allow-download > /tmp/tls-preparation.json \
    && MODFILE="$(python3 -c 'import json; print(json.load(open("/tmp/tls-preparation.json"))["audit_mod"])')" \
    && GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOEXPERIMENT=jsonv2 go build -mod=readonly -modfile="$MODFILE" -v -o V2bX -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor mdns trusttunnel mihomo" -trimpath -ldflags "-X github.com/PoriyaVali/V2bX/cmd.version=$VERSION -s -w -buildid="

# Release stage
FROM alpine
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime \
    && echo "Asia/Tehran" > /etc/timezone
RUN mkdir -p /etc/V2bX/
COPY --from=builder /app/V2bX /usr/local/bin/V2bX
ENTRYPOINT ["V2bX", "server", "-c", "/etc/V2bX/config.json"]
