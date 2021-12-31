# Copyright(C) Facebook, Inc. and its affiliates.
from os.path import join

from benchmark.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup():
        return (
            f'rm -r .db-* ; rm .*.json ; mkdir -p {PathMaker.results_path()}'
        )

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        return 'cargo build --quiet --release --features benchmark'

    @staticmethod
    def generate_keys(key_files, hosts, base_ports, shards, committee_file):
        assert isinstance(key_files, list)
        assert all(isinstance(x, str) for x in key_files)
        assert isinstance(hosts, list)
        assert all(isinstance(x, str) for x in hosts)
        assert isinstance(base_ports, list)
        assert all(isinstance(x, int) for x in base_ports)
        assert isinstance(shards, int)
        assert len(key_files) == len(hosts) and len(hosts) == len(base_ports)
        assert isinstance(committee_file, str)
        authorities = ''
        for (key_file, host, port) in zip(key_files, hosts, base_ports):
            authorities += f'{key_file}:Tcp:{host}:{port}:{shards} '
        return (
            f'./server generate-all --authorities {authorities}'
            f'--committee {committee_file} --max-output-coins 2'
        )

    @staticmethod
    def run_shard(keys, committee, store, shard, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(store, str)
        assert isinstance(shard, int)
        assert isinstance(debug, bool)
        #v = '-vvv' if debug else '-vv'
        return (
            'touch .empty.txt && '
            f'./server run --server {keys} --committee {committee} '
            f'--initial-accounts .empty.txt --shard {shard}'
        )

    @staticmethod
    def run_client(targets, rate, nodes, committee):
        assert isinstance(targets, list)
        assert all(isinstance(x, str) for x in targets)
        assert len(targets) > 1
        assert isinstance(rate, int) and rate >= 0
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)
        assert isinstance(committee, str)
        targets = ' '.join(targets)
        nodes = ' '.join(nodes) if nodes else ''
        return (
            f'./benchmark_client {targets} --rate {rate} '
            f'--committee {committee} --others {nodes}'
        )

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node, client = join(origin, 'server'), join(origin, 'benchmark_client')
        return f'rm server ; rm benchmark_client ; ln -s {node} . ; ln -s {client} .'
