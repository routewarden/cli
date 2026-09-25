# Multi-stage Dockerfile for RouteWarden CLI (rwarden) with embedded dashboard
# Stage 1: Build the Vite/React dashboard
FROM node:20-alpine AS webbuilder
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --prefer-offline
COPY web/ ./
RUN npm run build

# Stage 2: Build the Go binary with embedded dashboard assets
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# Copy the pre-built web assets so go:embed picks them up
COPY --from=webbuilder /web/dist ./web/dist

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /bin/rwarden .

# Stage 3: Minimal runtime image
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata docker-cli
COPY --from=builder /bin/rwarden /usr/local/bin/rwarden

WORKDIR /
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/rwarden"]
# Default: start the dashboard bound to all interfaces so it's reachable
# from the host when run with `docker run -p 9090:9090`
CMD ["dashboard", "--host", "0.0.0.0", "--no-open"]
