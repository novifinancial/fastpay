# Copyright(C) Facebook, Inc. and its affiliates.
import subprocess
from math import ceil
from os.path import basename, splitext
from time import sleep

from benchmark.commands import CommandMaker
from benchmark.config import BenchParameters, ConfigError, LocalCommittee, Key
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError, PathMaker


class LocalBench:
    BASE_PORT = 3000

    def __init__(self, bench_parameters_dict):
        try:
            self.bench_parameters = BenchParameters(bench_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

    def __getattr__(self, attr):
        return getattr(self.bench_parameters, attr)

    def _background_run(self, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'{command} 2> {log_file}'
        subprocess.run(['tmux', 'new', '-d', '-s', name, cmd], check=True)

    def _kill_nodes(self):
        try:
            cmd = CommandMaker.kill().split()
            subprocess.run(cmd, stderr=subprocess.DEVNULL)
        except subprocess.SubprocessError as e:
            raise BenchError('Failed to kill testbed', e)

    def run(self, debug=False):
        assert isinstance(debug, bool)
        Print.heading('Starting local benchmark')

        # Kill any previous testbed.
        self._kill_nodes()

        try:
            Print.info('Setting up testbed...')
            nodes, rate = self.nodes[0], self.rate[0]

            # Cleanup all files.
            cmd = f'{CommandMaker.clean_logs()} ; {CommandMaker.cleanup()}'
            subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
            sleep(0.5)  # Removing the store may take time.

            # Recompile the latest code.
            cmd = CommandMaker.compile().split()
            subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

            # Create alias for the client and nodes binary.
            cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
            subprocess.run([cmd], shell=True)

            # Generate configuration files.
            key_files = [PathMaker.key_file(i) for i in range(nodes)]
            cmd = CommandMaker.generate_all(
                key_files, PathMaker.parameters_file()
            )
            subprocess.run(cmd.split(), check=True)

            # Generate the committee file.
            names = [Key.from_file(x).name for x in key_files]
            committee = LocalCommittee(names, self.BASE_PORT, self.shards)
            committee.print(PathMaker.committee_file())

            # Run the clients (they will wait for the nodes to be ready).
            nodes_addresses = committee.addresses(self.faults)
            rate_share = ceil(rate / committee.total_shards())
            for i, shards in enumerate(nodes_addresses):
                for j, _ in shards:
                    cmd = CommandMaker.run_client(
                        [x[j][1] for x in nodes_addresses],
                        rate_share,
                        [x for y in nodes_addresses for _, x in y],
                        PathMaker.committee_file()
                    )
                    log_file = PathMaker.client_log_file(i, j)
                    self._background_run(cmd, log_file)

            # Run the shards (except the faulty ones).
            if self.coconut:
                parameters = PathMaker.parameters_file()
            else:
                parameters = None

            for i, shards in enumerate(nodes_addresses):
                for j, _ in shards:
                    cmd = CommandMaker.run_shard(
                        PathMaker.key_file(i),
                        PathMaker.committee_file(),
                        parameters,
                        PathMaker.db_path(i, j),
                        j,  # The shard's id.
                        debug=debug
                    )
                    log_file = PathMaker.shard_log_file(i, j)
                    self._background_run(cmd, log_file)

            # Wait for all transactions to be processed.
            Print.info(f'Running benchmark ({self.duration} sec)...')
            sleep(self.duration)
            self._kill_nodes()

            # Parse logs and return the parser.
            Print.info('Parsing logs...')
            return LogParser.process(PathMaker.logs_path(), faults=self.faults)

        except (subprocess.SubprocessError, ParseError) as e:
            self._kill_nodes()
            raise BenchError('Failed to run benchmark', e)
