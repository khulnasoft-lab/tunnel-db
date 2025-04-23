FROM golang:1.24-alpine@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c as builder

ARG DB_TYPE=tunnel

WORKDIR /build
COPY . /build
SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN apk --no-cache add make gzip

RUN DB_TYPE=${DB_TYPE} make db-all

FROM scratch
COPY --from=builder /build/assets/tunnel*.db.gz .
