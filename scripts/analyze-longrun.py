#!/usr/bin/env python3
"""Summarize long-run appliance samples (JSON lines) for the K12 long-run and sizing rows.

Each line holds one sample: ts, status, pending, oldest_pending, sysmon_lag,
quarantined, db_used, db_file, siem-logs, indexer-data, mem_used, fs_free, load1
and per-producer event counts.

sudo python3 scripts/analyze-longrun.py /var/tmp/xoc-longrun/samples.jsonl --since 2026-11-13T16:30:00Z
"""
import argparse
from datetime import datetime
import json
from pathlib import Path


def parse_time(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def summary(samples, keys):
    result = {}
    for key in keys:
        values = [s[key] for s in samples if isinstance(s.get(key), (int, float))]
        if values:
            result[key] = {'min': min(values), 'max': max(values), 'first': values[0], 'last': values[-1]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('samples', type=Path)
    parser.add_argument('--since', help='ignore samples before this UTC time (deploy gaps, backlog)')
    args = parser.parse_args()
    since = parse_time(args.since) if args.since else None
    samples = []
    for line in args.samples.read_text().splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if since and parse_time(value['ts']) < since:
            continue
        samples.append(value)
    if len(samples) < 2:
        raise SystemExit('Not enough samples in the window.')
    start, end = parse_time(samples[0]['ts']), parse_time(samples[-1]['ts'])
    hours = (end - start).total_seconds() / 3600
    gaps = [(a['ts'], b['ts']) for a, b in zip(samples, samples[1:])
            if (parse_time(b['ts']) - parse_time(a['ts'])).total_seconds() > 1500]
    not_ready = [s['ts'] for s in samples if s.get('status') != 'ready']
    stats = summary(samples, ['pending', 'oldest_pending', 'sysmon_lag', 'quarantined', 'db_used', 'db_file',
                              'siem-logs', 'indexer-data', 'mem_used', 'fs_free', 'load1'])
    first, last = samples[0].get('counts', {}), samples[-1].get('counts', {})
    storage = {k: stats[k]['last'] for k in ('db_file', 'siem-logs', 'indexer-data') if k in stats}
    report = {
        'window': {'start': samples[0]['ts'], 'end': samples[-1]['ts'], 'hours': round(hours, 2),
                   'samples': len(samples), 'gaps_over_25_min': gaps},
        'status': {'ready_samples': len(samples) - len(not_ready), 'not_ready_samples': not_ready},
        'latency_seconds': {k: stats[k] for k in ('oldest_pending', 'sysmon_lag') if k in stats},
        'memory_gib': {k: round(v / 1024**3, 2) for k, v in stats.get('mem_used', {}).items()},
        'storage_gib': {k: round(v / 1024**3, 2) for k, v in storage.items()},
        'storage_total_gib': round(sum(storage.values()) / 1024**3, 2),
        'db_used_gib': {k: round(v / 1024**3, 2) for k, v in stats.get('db_used', {}).items()},
        'filesystem_free_gib': {k: round(v / 1024**3, 1) for k, v in stats.get('fs_free', {}).items()},
        'load1': stats.get('load1'),
        'retained_events_by_producer': {'first': first, 'last': last},
    }
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
