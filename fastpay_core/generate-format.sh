#!/bin/bash
cd "`dirname $0`"/..
cargo run --example generate-format > fastpay_core/tests/staged/fastpay.yaml
