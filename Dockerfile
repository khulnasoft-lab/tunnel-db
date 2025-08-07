FROM golang:1.24-alpine@sha256:c8c5f95d64aa79b6547f3b626eb84b16a7ce18a139e3e9ca19a8c078b85ba80d as builder

ARG DB_TYPE=tunnel

WORKDIR /build
COPY . /build
SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN apk --no-cache add make gzip

RUN DB_TYPE=${DB_TYPE} make db-all

FROM scratch
COPY --from=builder /build/assets/tunnel*.db.gz .
