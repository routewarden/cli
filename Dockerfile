# Multi-stage Dockerfile for RouteWarden CLI (rwarden)
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /bin/rwarden .

FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata docker-cli
COPY --from=builder /bin/rwarden /usr/local/bin/rwarden

WORKDIR /
ENTRYPOINT ["/usr/local/bin/rwarden"]
CMD ["--help"]
