FROM golang:1.21-alpine@sha256:2414035b086e3c42b99654c8b26e6f5b1b1598080d65fd03c7f499552ff4dc94 as builder

ARG DB_TYPE=tunnel

WORKDIR /build
COPY . /build
SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN apk --no-cache add make gzip

RUN DB_TYPE=${DB_TYPE} make db-all

FROM scratch
COPY --from=builder /build/assets/tunnel*.db.gz .
