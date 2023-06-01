#syntax=docker/dockerfile:1.4
ARG GO_VERSION=1.18

FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.1.0 AS xx

FROM --platform=$BUILDPLATFORM golang:1.19-alpine AS base
RUN apk add --no-cache git
COPY --from=xx / /
WORKDIR /src

FROM base AS build
ARG TARGETPLATFORM
ENV CGO_ENABLED=0
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN --mount=target=/go/pkg/mod,type=cache \
    --mount=target=/root/.cache,type=cache \
    xx-go build -ldflags="${GO_LDFLAGS}" -o bin/guaccollect cmd/guaccollect/main.go
RUN --mount=target=/go/pkg/mod,type=cache \
    --mount=target=/root/.cache,type=cache \
    xx-go build -ldflags="${GO_LDFLAGS}" -o bin/guaccsub cmd/guaccsub/main.go
RUN --mount=target=/go/pkg/mod,type=cache \
    --mount=target=/root/.cache,type=cache \
    xx-go build -ldflags="${GO_LDFLAGS}" -o bin/guacgql cmd/guacgql/main.go
RUN --mount=target=/go/pkg/mod,type=cache \
    --mount=target=/root/.cache,type=cache \
    xx-go build -ldflags="${GO_LDFLAGS}" -o bin/guacingest cmd/guacingest/main.go
RUN --mount=target=/go/pkg/mod,type=cache \
    --mount=target=/root/.cache,type=cache \
    xx-go build -ldflags="${GO_LDFLAGS}" -o bin/guacone cmd/guacone/main.go

FROM cgr.dev/chainguard/static:latest-glibc
WORKDIR /app
COPY --from=build /src/bin /opt/guac