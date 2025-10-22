#!/usr/bin/env bash
set -euo pipefail

# Prefer generating a tiny sample pcap locally to avoid flaky external URLs
cargo run --quiet --bin gen_sample

echo "Sample written to samples/http.cap"
