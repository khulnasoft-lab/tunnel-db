FROM golang:1.24-alpine@sha256:daae04ebad0c21149979cd8e9db38f565ecefd8547cf4a591240dc1972cf1399 as builder

ARG DB_TYPE=tunnel

WORKDIR /build
COPY . /build
SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN apk --no-cache add make gzip

RUN DB_TYPE=${DB_TYPE} make db-all

FROM scratch
COPY --from=builder /build/assets/tunnel*.db.gz .
