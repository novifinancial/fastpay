# Copyright(C) Facebook, Inc. and its affiliates.
from collections import defaultdict
from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search
from statistics import mean

from benchmark.utils import Print


class ParseError(Exception):
    pass


class LogParser:
    def __init__(self, clients, shards, num_nodes=0, faults=0):
        inputs = [clients, shards]
        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        assert all(x for x in inputs)

        self.faults = faults
        if isinstance(faults, int) and isinstance(num_nodes, int):
            self.committee_size = int(num_nodes) + int(faults)
            self.shards = len(shards) // num_nodes
        else:
            self.committee_size = '?'
            self.shards = '?'

        # Parse the clients logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_clients, clients)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse clients\' logs: {e}')
        self.rate, self.start, misses, sent_samples, certificates = \
            zip(*results)
        self.misses = sum(misses)
        self.sent_samples = {k: v for x in sent_samples for k, v in x.items()}
        self.certificates = {k: v for x in certificates for k, v in x.items()}

        # Parse the shards logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_shards, shards)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse shards\' logs: {e}')
        shards_ips, commits = zip(*results)
        self.commits = self._keep_earliest_validity(
            [x.items() for x in commits]
        )

        # Determine whether the primary and the workers are collocated.
        self.collocate = num_nodes == len(set(shards_ips))

        # Check whether clients missed their target rate.
        if self.misses != 0:
            Print.warn(
                f'Clients missed their target rate {self.misses:,} time(s)'
            )

    def _keep_earliest(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or merged[k] > v:
                    merged[k] = v
        return merged

    def _keep_earliest_validity(self, input):
        # Keep the earliest f+1 timestamp.
        if isinstance(self.committee_size, int):
            validity = int((self.committee_size + 2) / 3)
        else:
            validity = 1

        merged = defaultdict(list)
        for x in input:
            for k, v in x:
                merged[k] += [v]

        for k, v in merged.items():
            values = v.copy()
            values.sort()
            merged[k] = max(values[:validity])

        return merged

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise ParseError('Client(s) panicked')

        rate = int(search(r'Transactions rate: (\d+)', log).group(1))

        tmp = search(r'\[(.*Z) .* Start ', log).group(1)
        start = self._to_posix(tmp)

        misses = len(findall(r'rate too high', log))

        tmp = findall(r'\[(.*Z) .* sample transaction (\d+)', log)
        samples = {int(d): self._to_posix(t) for t, d in tmp}

        tmp = findall(r'\[(.*Z) .* certificate (\d+)', log)
        tmp = [(int(d), self._to_posix(t)) for t, d in tmp]
        certificates = self._keep_earliest([tmp])  # Unnecessary

        return rate, start, misses, samples, certificates

    def _parse_shards(self, log):
        if search(r'(?:panic|Error)', log) is not None:
            raise ParseError('Shard(s) panicked')

        ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

        tmp = findall(r'\[(.*Z) .* certificate (\d+)', log)
        tmp = [(int(d), self._to_posix(t)) for t, d in tmp]
        certificates = self._keep_earliest([tmp])  # Unnecessary

        return ip, certificates

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    def _client_throughput(self):
        if not self.certificates:
            return 0, 0
        start, end = min(self.start), max(self.certificates.values())
        duration = end - start
        txs = len(self.certificates)
        tps = txs / duration
        return tps, duration

    def _client_latency(self):
        latency = []
        for id, start in self.sent_samples.items():
            if id in self.certificates:
                end = self.certificates[id]
                assert end >= start
                latency += [end-start]
        return mean(latency) if latency else 0

    def _end_to_end_throughput(self):
        if not self.commits:
            return 0, 0
        start, end = min(self.start), max(self.commits.values())
        duration = end - start
        txs = len(self.commits)
        tps = txs / duration
        return tps, duration

    def _end_to_end_latency(self):
        latency = []
        for id, start in self.sent_samples.items():
            if id in self.commits:
                end = self.commits[id]
                assert end >= start
                latency += [end-start]
        return mean(latency) if latency else 0

    def result(self):
        client_latency = self._client_latency() * 1_000
        client_tps, _ = self._client_throughput()
        end_to_end_tps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1_000

        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Faults: {self.faults} node(s)\n'
            f' Committee size: {self.committee_size} node(s)\n'
            f' Shard(s) per node: {self.shards} shard(s)\n'
            f' Collocate shards: {self.collocate}\n'
            f' Input rate: {sum(self.rate):,} tx/s\n'
            f' Execution time: {round(duration):,} s\n'
            '\n'
            ' + RESULTS:\n'
            f' Client TPS: {round(client_tps):,} tx/s\n'
            f' Client latency: {round(client_latency):,} ms\n'
            f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
            '-----------------------------------------\n'
        )

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    @classmethod
    def process(cls, directory, num_nodes=0, faults=0):
        assert isinstance(directory, str)

        clients = []
        for filename in sorted(glob(join(directory, 'client-*.log'))):
            with open(filename, 'r') as f:
                clients += [f.read()]
        shards = []
        for filename in sorted(glob(join(directory, 'shard-*.log'))):
            with open(filename, 'r') as f:
                shards += [f.read()]

        num_nodes = len(glob(join(directory, 'shard-*-0.log')))
        return cls(clients, shards, num_nodes, faults)
