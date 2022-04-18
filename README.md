# FastPay

[![Build Status](https://github.com/novifinancial/fastpay/actions/workflows/rust.yml/badge.svg)](https://github.com/novifinancial/fastpay/actions/workflows/rust.yml)
[![License](https://img.shields.io/badge/license-Apache-green.svg)](LICENSE.md)

This repository is dedicated to sharing material related to the FastPay protocol, developed at Novi Financial (formerly Calibra). Software is provided for research-purpose only and is not meant to be used in production.

## Summary

FastPay allows a set of distributed authorities, some of which are Byzantine, to maintain a high-integrity and availability settlement system for pre-funded payments. It can be used to settle payments in a native unit of value (crypto-currency), or as a financial side-infrastructure to support retail payments in fiat currencies. FastPay is based on Byzantine Consistent Broadcast as its core primitive, foregoing the expenses of full atomic commit channels (consensus). The resulting system has low-latency for both confirmation and payment finality. Remarkably, each authority can be sharded across many machines to allow unbounded horizontal scalability. Our experiments demonstrate intra-continental confirmation latency of less than 100ms, making FastPay applicable to point of sale payments. In laboratory environments, we achieve over 80,000 transactions per second with 20 authorities---surpassing the requirements of current retail card payment networks, while significantly increasing their robustness.

## Quickstart with FastPay Prototype

```bash
cargo build --release -p fastpay
cd target/release
rm -f *.json *.txt

# Make sure to clean up child processes on exit.
trap 'kill $(jobs -p)' EXIT

# Create configuration files for 4 authorities with 4 shards each.
# * Private server states are stored in `server*.json`.
# * `committee.json` is the public description of the FastPay committee.

# echo 'null' > committee.json  # no coconut parameters
# for I in 1 2 3 4
# do
#    ./server generate --server server_"$I".json --host 127.0.0.1 --port 9"$I"00 --shards 4 >> committee.json
# done

# With coconut trusted setup:
./server generate-all --authorities \
   server_1.json:udp:127.0.0.1:9100:4 \
   server_2.json:udp:127.0.0.1:9200:4 \
   server_3.json:udp:127.0.0.1:9300:4 \
   server_4.json:udp:127.0.0.1:9400:4 \
--committee committee.json

# Create configuration files for 1000 user accounts.
# * Private account states are stored in one local wallet `accounts.json`.
# * `initial_accounts.txt` is used to mint the corresponding initial balances at startup on the server side.
./client --committee committee.json --accounts accounts.json create_initial_accounts 1000 --initial-funding 100 >> initial_accounts.txt

# Start servers
for I in 1 2 3 4
do
    for J in $(seq 0 3)
    do
        ./server run --server server_"$I".json --shard "$J" --initial-accounts initial_accounts.txt --committee committee.json &
    done
 done

# Query balance for first and last user account
ACCOUNT1="`head -n 1 initial_accounts.txt | awk -F: '{ print $1 }'`"
ACCOUNT2="`tail -n -1 initial_accounts.txt | awk -F: '{ print $1 }'`"
./client --committee committee.json --accounts accounts.json query_balance "$ACCOUNT1"
./client --committee committee.json --accounts accounts.json query_balance "$ACCOUNT2"

# Transfer 10 units
./client --committee committee.json --accounts accounts.json transfer 10 --from "$ACCOUNT1" --to "$ACCOUNT2"

# Query balances again
./client --committee committee.json --accounts accounts.json query_balance "$ACCOUNT1"
./client --committee committee.json --accounts accounts.json query_balance "$ACCOUNT2"

# Launch local benchmark using all user accounts
./client --committee committee.json --accounts accounts.json benchmark

# Create derived account
ACCOUNT3="`./client --committee committee.json --accounts accounts.json open_account --from "$ACCOUNT1"`"

# Create coins (1 transparent and 1 opaque) into account #3 by withdrawing publicly from account #1
./client --committee committee.json --accounts accounts.json spend_and_create_coins --from "$ACCOUNT2" --amount 110 --to-coins "$ACCOUNT3:50" "($ACCOUNT3:60)"

# Inspect state of derived account
fgrep '"account_id"':"$ACCOUNT3" accounts.json

# List the coins in account #3
./client --committee committee.json --accounts accounts.json list_coins "$ACCOUNT3" | tee coins.txt

# Spend and transfer one of the coins back to the first account
./client --committee committee.json --accounts accounts.json spend_and_transfer --from "$ACCOUNT3" --seeds $(awk -F: '{ print $1 }' coins.txt) --to "$ACCOUNT1"

# Query the balance of the first account
./client --committee committee.json --accounts accounts.json query_balance "$ACCOUNT1"

# Additional local benchmark
./bench

cd ../..
```

## References

* [FastPay: High-Performance Byzantine Fault Tolerant Settlement](https://arxiv.org/abs/2003.11506)

## Contributing

Read our [Contributing guide](https://developers.libra.org/docs/community/contributing).

## License

The content of this repository is licensed as [Apache 2.0](https://github.com/novifinancial/fastpay/blob/main/LICENSE)
