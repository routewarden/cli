# syntax=docker/dockerfile:1.7
# Multi-stage Dockerfile for RouteWarden CLI (rwarden)
#
# Build-time args injected by docker buildx / goreleaser:
#   BUILDPLATFORM  – native platform of the builder host  (e.g. linux/amd64)
#   TARGETOS       – target OS                            (e.g. linux)
#   TARGETARCH     – target CPU arch                      (e.g. arm64)
#   VERSION        – binary version string                (e.g. v4.2.0)
#
# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Build the Go binary on native platform with cross-compilation
# ──────────────────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /bin/rwarden .

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Minimal runtime image
# ──────────────────────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata docker-cli docker-cli-compose
COPY --from=builder /bin/rwarden /usr/local/bin/rwarden

WORKDIR /
EXPOSE 3000 3100 12345 1514/udp
ENTRYPOINT ["/usr/local/bin/rwarden"]
CMD ["--help"]
