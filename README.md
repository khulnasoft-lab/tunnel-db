# Tunnel DB

![Build DB](https://github.com/khulnasoft-lab/tunnel-db/workflows/Tunnel%20DB/badge.svg)
[![GitHub Release][release-img]][release] ![Downloads][download] [![Go Report Card][report-card-img]][report-card] [![Go Doc][go-doc-img]][go-doc] [![License][license-img]][license]

[download]: https://img.shields.io/github/downloads/khulnasoft-lab/tunnel-db/total?logo=github
[release-img]: https://img.shields.io/github/release/khulnasoft-lab/tunnel-db.svg?logo=github
[release]: https://github.com/khulnasoft-lab/tunnel-db/releases
[report-card-img]: https://goreportcard.com/badge/github.com/khulnasoft-lab/tunnel-db
[report-card]: https://goreportcard.com/report/github.com/khulnasoft-lab/tunnel-db
[go-doc-img]: https://godoc.org/github.com/khulnasoft-lab/tunnel-db?status.svg
[go-doc]: https://godoc.org/github.com/khulnasoft-lab/tunnel-db
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://github.com/khulnasoft-lab/tunnel-db/blob/main/LICENSE

## 🚀 Overview
`tunnel-db` is a CLI tool and library for managing Tunnel DB, a database containing vulnerability information from sources such as NVD, Red Hat, Debian, and others.

### 📚 Library
Tunnel internally uses `tunnel-db` to manage its vulnerability database efficiently.

### 🛠️ CLI Tool
The `tunnel-db` CLI allows users to build, compact, and compress vulnerability databases. It integrates with GitHub Actions to periodically update the database and push it to the GitHub Container Registry.

```sh
NAME:
   tunnel-db - Tunnel DB builder

USAGE:
   tunnel-db [global options] command [command options] image_name

VERSION:
   0.0.1

COMMANDS:
   build    Build a database file
   help, h  Show help for commands

GLOBAL OPTIONS:
   --help, -h     Show help
   --version, -v  Print the version
```

## 🔧 Building Tunnel DB
To build `tunnel-db` locally, follow these steps:

```sh
make db-fetch-langs db-fetch-vuln-list  # Download advisories and required files
make build                              # Compile `tunnel-db` binary
make db-build                           # Build the database
make db-compact                         # Compact the database
make db-compress                        # Compress database into `db.tar.gz`
```

### 📦 Pushing to a Registry (GHCR)
To build and push a `tunnel-db` image to GitHub Container Registry using [Oras CLI](https://oras.land/cli/):

```sh
oras push --artifact-type application/vnd.khulnasoft.tunnel.config.v1+json \
  "ghcr.io/khulnasoft-lab/tunnel-db:2" \
  db.tar.gz:application/vnd.khulnasoft.tunnel.db.layer.v1.tar+gzip
```

## ⏳ Update Interval
- Tunnel DB is rebuilt every **6 hours**.
- The default update interval in the metadata file is **24 hours**.
- For more frequent updates, you can manually upload a new database.

## 📥 Downloading the Vulnerability Database

### 🔴 Version 1 (Deprecated)
Tunnel DB v1 support ended in **February 2023**. Upgrade to Tunnel **v0.23.0 or later**.
More details in [this discussion](https://github.com/khulnasoft/tunnel/discussions/1653).

### 🟢 Version 2 (Current)
Tunnel DB v2 is hosted on [GitHub Container Registry (GHCR)](https://github.com/orgs/khulnasoft-lab/packages/container/package/tunnel-db).

#### ✅ Using Tunnel
```sh
TUNNEL_TEMP_DIR=$(mktemp -d)
tunnel --cache-dir $TUNNEL_TEMP_DIR image --download-db-only
tar -cf ./db.tar.gz -C $TUNNEL_TEMP_DIR/db metadata.json tunnel.db
rm -rf $TUNNEL_TEMP_DIR
```

#### ✅ Using Oras CLI
For Oras **v0.13.0+**:
```sh
oras pull ghcr.io/khulnasoft-lab/tunnel-db:2
```

For Oras **< v0.13.0**:
```sh
oras pull -a ghcr.io/khulnasoft-lab/tunnel-db:2
```

## 🌍 Air-Gapped Environments
The database can be used in [air-gapped environments](https://khulnasoft.github.io/tunnel/latest/docs/advanced/air-gap/) where internet access is restricted.

---

🚀 **Stay Updated** – Check out the [official documentation](https://khulnasoft.github.io/tunnel/) for more details and updates.

