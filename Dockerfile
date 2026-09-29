# syntax=docker/dockerfile:1.7
# Multi-stage Dockerfile for RouteWarden CLI (rwarden) with embedded dashboard
#
# Build-time args injected by docker buildx / goreleaser:
#   BUILDPLATFORM  – native platform of the builder host  (e.g. linux/amd64)
#   TARGETOS       – target OS                            (e.g. linux)
#   TARGETARCH     – target CPU arch                      (e.g. arm64)
#   VERSION        – binary version string                (e.g. v4.0.0)
#
# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Build the Vite/React dashboard on the native builder platform
# ──────────────────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM node:20-alpine AS webbuilder
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline
COPY web/ ./
RUN npm run build

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Build the Go binary on native platform with cross-compilation
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
# Copy pre-built web assets from /dashboard/dist (Vite's outDir: '../dashboard/dist')
# so Go's `//go:embed all:dist` inside package dashboard embeds them
COPY --from=webbuilder /dashboard/dist ./dashboard/dist

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
# Stage 3: Minimal runtime image
# ──────────────────────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata docker-cli
COPY --from=builder /bin/rwarden /usr/local/bin/rwarden

WORKDIR /
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/rwarden"]
# Default: start the dashboard bound to all interfaces so it's reachable
# from the host when run with `docker run -p 9090:9090`
CMD ["dashboard", "--host", "0.0.0.0", "--no-open"]
