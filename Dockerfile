FROM golang:1.25-alpine@sha256:77dd832edf2752dafd030693bef196abb24dcba3a2bc3d7a6227a7a1dae73169 as builder

ARG DB_TYPE=tunnel

WORKDIR /build
COPY . /build
SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN apk --no-cache add make gzip

RUN DB_TYPE=${DB_TYPE} make db-all

FROM scratch
COPY --from=builder /build/assets/tunnel*.db.gz .
