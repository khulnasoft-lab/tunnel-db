FROM golang:1.24-alpine@sha256:fc2cff6625f3c1c92e6c85938ac5bd09034ad0d4bc2dfb08278020b68540dbb5 as builder

ARG DB_TYPE=tunnel

WORKDIR /build
COPY . /build
SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN apk --no-cache add make gzip

RUN DB_TYPE=${DB_TYPE} make db-all

FROM scratch
COPY --from=builder /build/assets/tunnel*.db.gz .
