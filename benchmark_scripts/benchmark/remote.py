# Copyright(C) Facebook, Inc. and its affiliates.
from collections import OrderedDict
from fabric import Connection, ThreadingGroup as Group
from fabric.exceptions import GroupException
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from os.path import basename, splitext
from time import sleep
from math import ceil
from copy import deepcopy
import subprocess

from benchmark.config import Committee, Key, BenchParameters, ConfigError
from benchmark.utils import BenchError, Print, PathMaker, progress_bar
from benchmark.commands import CommandMaker
from benchmark.logs import LogParser, ParseError
from benchmark.instance import InstanceManager


class FabricError(Exception):
    ''' Wrapper for Fabric exception with a meaningfull error message. '''

    def __init__(self, error):
        assert isinstance(error, GroupException)
        message = list(error.result.values())[-1]
        super().__init__(message)


class ExecutionError(Exception):
    pass


class Bench:
    def __init__(self, ctx):
        self.manager = InstanceManager.make()
        self.settings = self.manager.settings
        try:
            ctx.connect_kwargs.pkey = RSAKey.from_private_key_file(
                self.manager.settings.key_path
            )
            self.connect = ctx.connect_kwargs
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError('Failed to load SSH key', e)

    def _check_stderr(self, output):
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)

    def install(self):
        Print.info('Installing rust and cloning the repo...')
        cmd = [
            'sudo apt-get update',
            'sudo apt-get -y upgrade',
            'sudo apt-get -y autoremove',

            # The following dependencies prevent the error: [error: linker `cc` not found].
            'sudo apt-get -y install build-essential',
            'sudo apt-get -y install cmake',

            # Install rust (non-interactive).
            'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
            'source $HOME/.cargo/env',
            'rustup default stable',

            # This is missing from the Rocksdb installer (needed for Rocksdb).
            'sudo apt-get install -y clang',

            # Clone the repo.
            f'(git clone {self.settings.repo_url} || (cd {self.settings.repo_name} ; git pull))'
        ]
        hosts = self.manager.hosts(flat=True)
        try:
            g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
            g.run(' && '.join(cmd), hide=True)
            Print.heading(f'Initialized testbed of {len(hosts)} nodes')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to install repo on testbed', e)

    def kill(self, hosts=[], delete_logs=False):
        assert isinstance(hosts, list)
        assert isinstance(delete_logs, bool)
        hosts = hosts if hosts else self.manager.hosts(flat=True)
        delete_logs = CommandMaker.clean_logs() if delete_logs else 'true'
        cmd = [delete_logs, f'({CommandMaker.kill()} || true)']
        try:
            g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
            g.run(' && '.join(cmd), hide=True)
        except GroupException as e:
            raise BenchError('Failed to kill nodes', FabricError(e))

    def _rate_share(self, committee, nodes, shards, rate, node_idx, shard_idx):
        # Handle the common case.
        if rate >= nodes * shards:
            return ceil(rate / committee.total_shards())

        # Handle small transaction rates.
        if rate <= shards:
            if node_idx == 0 and shard_idx < rate:
                return 1
        else:
            if node_idx == 0:
                r = rate % shards
                share = int(rate / shards)
                if shard_idx < r:
                    return share + 1
                else:
                    return share

        return 0

    def _select_hosts(self, bench_parameters):
        # Collocate all shards on the same machine.
        if bench_parameters.collocate:
            nodes = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.hosts()
            if sum(len(x) for x in hosts.values()) < nodes:
                return []

            # Select the hosts in different data centers.
            ordered = zip(*hosts.values())
            ordered = [x for y in ordered for x in y]
            return ordered[:nodes]

        # Spawn each shard on a different machine. Each authority runs in
        # a single data center.
        else:
            nodes = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.hosts()
            if len(hosts.keys()) < nodes:
                return []
            for ips in hosts.values():
                if len(ips) < bench_parameters.shards:
                    return []

            # Ensure the shards of a single authority are in the same region.
            selected = []
            for region in list(hosts.keys())[:nodes]:
                ips = list(hosts[region])[:bench_parameters.shards]
                selected.append(ips)
            return selected

    def _background_run(self, host, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'tmux new -d -s "{name}" "{command} |& tee {log_file}"'
        c = Connection(host, user='ubuntu', connect_kwargs=self.connect)
        output = c.run(cmd, hide=True)
        self._check_stderr(output)

    def _update(self, hosts, collocate):
        if collocate:
            ips = list(set(hosts))
        else:
            ips = list(set([x for y in hosts for x in y]))

        Print.info(
            f'Updating {len(ips)} machines (branch "{self.settings.branch}")...'
        )
        cmd = [
            f'(cd {self.settings.repo_name} && git fetch -f)',
            f'(cd {self.settings.repo_name} && git checkout -f {self.settings.branch})',
            f'(cd {self.settings.repo_name} && git pull -f)',
            'source $HOME/.cargo/env',
            f'(cd {self.settings.repo_name} && {CommandMaker.compile()})',
            CommandMaker.alias_binaries(
                f'./{self.settings.repo_name}/target/release/'
            )
        ]
        g = Group(*ips, user='ubuntu', connect_kwargs=self.connect)
        g.run(' && '.join(cmd), hide=True)

    def _config(self, hosts, bench_parameters):
        Print.info('Generating configuration files...')

        # Cleanup all local configuration files.
        cmd = CommandMaker.cleanup()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        # Recompile the latest code.
        cmd = CommandMaker.compile().split()
        subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

        # Create alias for the client and nodes binary.
        cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
        subprocess.run([cmd], shell=True)

        # Generate configuration files.
        key_files = [PathMaker.key_file(i) for i in range(len(hosts))]
        cmd = CommandMaker.generate_all(
            key_files,
            PathMaker.parameters_file(),
            PathMaker.master_secret_file()
        )
        subprocess.run(cmd.split(), check=True)

        names = [Key.from_file(x).name for x in key_files]

        if bench_parameters.collocate:
            shards = bench_parameters.shards
            addresses = OrderedDict(
                (x, [y] * shards) for x, y in zip(names, hosts)
            )
        else:
            addresses = OrderedDict(
                (x, y) for x, y in zip(names, hosts)
            )
        committee = Committee(addresses, self.settings.base_port)
        committee.print(PathMaker.committee_file())

        # Cleanup all nodes and upload configuration files.
        names = names[:len(names)-bench_parameters.faults]
        progress = progress_bar(names, prefix='Uploading config files:')
        for i, name in enumerate(progress):
            for ip in committee.ips(name):
                c = Connection(ip, user='ubuntu', connect_kwargs=self.connect)
                c.run(f'{CommandMaker.cleanup()} || true', hide=True)
                c.put(PathMaker.committee_file(), '.')
                c.put(PathMaker.key_file(i), '.')
                c.put(PathMaker.parameters_file(), '.')
                c.put(PathMaker.master_secret_file(), '.')

        return committee

    def _run_single(self, rate, committee, bench_parameters, debug=False):
        faults = bench_parameters.faults

        # Kill any potentially unfinished run and delete logs.
        hosts = committee.ips()
        self.kill(hosts=hosts, delete_logs=True)

        # Check whether to run coconut or not.
        if bench_parameters.coconut:
            parameters = PathMaker.parameters_file()
            master_secret = PathMaker.master_secret_file()
        else:
            parameters = None
            master_secret = None

        # Run the clients (they will wait for the nodes to be ready).
        # Filter all faulty nodes from the client addresses (or they will wait
        # for the faulty nodes to be online).
        Print.info('Booting clients...')
        nodes_addresses = committee.addresses(faults)
        for i, shards in enumerate(nodes_addresses):
            for j, address in shards:
                host = Committee.ip(address)
                rate_share = self._rate_share(
                    committee,
                    committee.size(),
                    bench_parameters.shards,
                    rate,
                    i,
                    j
                )
                cmd = CommandMaker.run_client(
                    [x[j][1] for x in nodes_addresses],
                    rate_share,
                    [x for y in nodes_addresses for _, x in y],
                    PathMaker.committee_file(),
                    parameters,
                    master_secret
                )
                log_file = PathMaker.client_log_file(i, j)
                self._background_run(host, cmd, log_file)

        # Run the shards (except the faulty ones).
        Print.info('Booting shards...')
        for i, shards in enumerate(nodes_addresses):
            for j, address in shards:
                host = Committee.ip(address)
                cmd = CommandMaker.run_shard(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    parameters,
                    PathMaker.db_path(i, j),
                    j,  # The shard's id.
                    debug=debug
                )
                log_file = PathMaker.shard_log_file(i, j)
                self._background_run(host, cmd, log_file)

        # Wait for all transactions to be processed.
        duration = bench_parameters.duration
        for _ in progress_bar(range(20), prefix=f'Running benchmark ({duration} sec):'):
            sleep(ceil(duration / 20))
        self.kill(hosts=hosts, delete_logs=False)

    def _logs(self, committee, faults):
        # Delete local logs (if any).
        cmd = CommandMaker.clean_logs()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        # Download log files.
        nodes_addresses = committee.addresses(faults)
        progress = progress_bar(
            nodes_addresses, prefix='Downloading shards logs:'
        )
        for i, addresses in enumerate(progress):
            for j, address in addresses:
                host = Committee.ip(address)
                c = Connection(
                    host, user='ubuntu', connect_kwargs=self.connect
                )
                c.get(
                    PathMaker.client_log_file(i, j),
                    local=PathMaker.client_log_file(i, j)
                )
                c.get(
                    PathMaker.shard_log_file(i, j),
                    local=PathMaker.shard_log_file(i, j)
                )

        # Parse logs and return the parser.
        Print.info('Parsing logs and computing performance...')
        return LogParser.process(PathMaker.logs_path(), faults=faults)

    def run(self, bench_parameters_dict, debug=False):
        assert isinstance(debug, bool)
        Print.heading('Starting remote benchmark')
        try:
            bench_parameters = BenchParameters(bench_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

        # Select which hosts to use.
        selected_hosts = self._select_hosts(bench_parameters)
        if not selected_hosts:
            Print.warn('There are not enough instances available')
            return

        # Update nodes.
        try:
            self._update(selected_hosts, bench_parameters.collocate)
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to update nodes', e)

        # Run benchmarks.
        for n in bench_parameters.nodes:
            Print.heading(f'\nBenchmarking {n} nodes')

            # Upload all configuration files.
            try:
                committee = self._config(
                    selected_hosts, bench_parameters
                )
            except (subprocess.SubprocessError, GroupException) as e:
                e = FabricError(e) if isinstance(e, GroupException) else e
                raise BenchError('Failed to configure nodes', e)

            # Remove faulty nodes.
            committee.remove_nodes(committee.size() - n)

            # Run the benchmarks.
            for r in bench_parameters.rate:
                Print.heading(f'\nRunning {n} nodes (input rate: {r:,} tx/s)')
                for i in range(bench_parameters.runs):
                    Print.heading(f'Run {i+1}/{bench_parameters.runs}')
                    try:
                        self._run_single(
                            r, committee, bench_parameters, debug
                        )

                        faults = bench_parameters.faults
                        logger = self._logs(committee, faults)
                        logger.print(PathMaker.result_file(
                            faults,
                            n,
                            bench_parameters.shards,
                            bench_parameters.collocate,
                            r,
                            bench_parameters.coconut
                        ))
                    except (subprocess.SubprocessError, GroupException, ParseError) as e:
                        self.kill(hosts=selected_hosts)
                        if isinstance(e, GroupException):
                            e = FabricError(e)
                        Print.error(BenchError('Benchmark failed', e))
                        continue
