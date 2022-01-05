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
    def generate_all(key_files, parameters_file):
        assert isinstance(key_files, list)
        assert isinstance(parameters_file, str)
        key_files = ' '.join(key_files)
        return (
            f'./benchmark_server generate {key_files} '
            f'--parameters {parameters_file}'
        )

    @staticmethod
    def run_shard(keys, committee, parameters, store, shard, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str) or parameters is None
        assert isinstance(store, str)
        assert isinstance(shard, int)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        params = f'--parameters {parameters} ' if parameters is not None else ''
        return (
            f'./benchmark_server {v} run --keys {keys} --committee {committee} '
            f'{params}--store {store} --shard {shard}'
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
        node = join(origin, 'benchmark_server')
        client = join(origin, 'benchmark_client')
        return (
            'rm benchmark_server ; rm benchmark_client '
            f'; ln -s {node} . ; ln -s {client} .'
        )
