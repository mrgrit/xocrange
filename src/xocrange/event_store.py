"""Private, transactional evidence/event store and durable Wazuh outbox."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

from .documents import canonical
from .errors import XocError
from .events import Context, normalize, SOURCES


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Store:
    def __init__(self, directory, identity=('community', 'local')):
        # (tenant_id, range_id) stamped on newly normalized events; see entitlements.collection_identity.
        self.identity = tuple(identity)
        self.directory = Path(directory)
        if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
            raise XocError("unsafe_store", "Evidence directory must not traverse symlinks.")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.stat().st_mode & 0o077 or self.directory.stat().st_uid != os.geteuid():
            raise XocError("unsafe_store", "Evidence directory must be private and owned by the current user.")
        path = self.directory / "events.sqlite3"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid():
            raise XocError("unsafe_store", "Evidence database must be private and owned by the current user.")
        self.db = sqlite3.connect(path, timeout=30)
        self.db.row_factory = sqlite3.Row
        # Takes effect for a new database (before any table exists); an older
        # store keeps auto_vacuum=0 until an explicit offline VACUUM. Setting
        # it takes the write lock even when unchanged, so a reader such as
        # `xoc siem status` would wait behind the collector and time out.
        if self.db.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
            self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        from .retention import policy
        self.policy = policy(self.directory)
        self.db.execute('PRAGMA max_page_count=' + str(self.policy['database_bytes']//self.db.execute('PRAGMA page_size').fetchone()[0]))
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS records (
          ref TEXT PRIMARY KEY, source TEXT NOT NULL, observed TEXT NOT NULL,
          sha256 TEXT NOT NULL, raw BLOB NOT NULL, error TEXT);
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, ref TEXT NOT NULL REFERENCES records(ref), producer TEXT NOT NULL,
          observed TEXT NOT NULL, event TEXT NOT NULL, sent TEXT, confirmed TEXT, rule_id TEXT);
        CREATE INDEX IF NOT EXISTS events_producer_time ON events(producer, observed);
        CREATE INDEX IF NOT EXISTS events_pending ON events(confirmed, sent);
        CREATE INDEX IF NOT EXISTS events_status ON events(producer, confirmed);
        CREATE INDEX IF NOT EXISTS records_quarantined ON records(error) WHERE error IS NOT NULL;
        CREATE INDEX IF NOT EXISTS records_observed ON records(observed);
        CREATE INDEX IF NOT EXISTS events_observed ON events(observed);
        CREATE INDEX IF NOT EXISTS events_ref ON events(ref);
        CREATE INDEX IF NOT EXISTS events_delivery_producer ON events(producer,observed) WHERE confirmed IS NULL;
        CREATE INDEX IF NOT EXISTS events_delivery_time ON events(observed) WHERE confirmed IS NULL;
        CREATE TABLE IF NOT EXISTS cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS health (source TEXT PRIMARY KEY, checked TEXT NOT NULL, status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS processing_errors (
          id TEXT PRIMARY KEY, observed TEXT NOT NULL, source TEXT NOT NULL,
          error TEXT NOT NULL, raw BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS wazuh_alerts (
          id TEXT PRIMARY KEY, observed TEXT NOT NULL, raw BLOB NOT NULL, sha256 TEXT NOT NULL,
          document TEXT NOT NULL, event_id TEXT, indexed TEXT);
        CREATE INDEX IF NOT EXISTS native_alerts_pending ON wazuh_alerts(indexed,observed);
        CREATE INDEX IF NOT EXISTS native_alerts_observed ON wazuh_alerts(observed);
        CREATE TABLE IF NOT EXISTS native_inputs (
          id TEXT PRIMARY KEY, ref TEXT NOT NULL REFERENCES records(ref) ON DELETE CASCADE,
          source TEXT NOT NULL, ordinal INTEGER NOT NULL, observed TEXT NOT NULL,
          event_id TEXT, frame_sha256 TEXT, sent TEXT, confirmed TEXT, decoder TEXT, error TEXT);
        CREATE INDEX IF NOT EXISTS native_inputs_pending ON native_inputs(confirmed,sent,observed);
        CREATE INDEX IF NOT EXISTS native_inputs_ref ON native_inputs(ref);
        CREATE INDEX IF NOT EXISTS native_inputs_source_pending ON native_inputs(source,confirmed,observed);
        CREATE INDEX IF NOT EXISTS native_inputs_source_observed ON native_inputs(source,observed);
        CREATE INDEX IF NOT EXISTS native_alerts_event ON wazuh_alerts(event_id,indexed);
        CREATE INDEX IF NOT EXISTS native_alerts_unlinked_pending ON wazuh_alerts(indexed,event_id,observed);
        ''')
        if 'source_id' not in {r[1] for r in self.db.execute('PRAGMA table_info(records)')}:
            self.db.execute('ALTER TABLE records ADD COLUMN source_id TEXT')
            self.db.commit()
        if 'indexed' not in {r[1] for r in self.db.execute('PRAGMA table_info(events)')}:
            self.db.execute('ALTER TABLE events ADD COLUMN indexed TEXT')
            self.db.commit()
        if 'annotation' not in {r[1] for r in self.db.execute('PRAGMA table_info(wazuh_alerts)')}:
            self.db.execute('ALTER TABLE wazuh_alerts ADD COLUMN annotation TEXT')
            self.db.commit()
        # Before the collector separated them, an unterminated Manager output tail
        # (left by a restore that shortened the file) was stored as an evidence record
        # with no adapter and quarantined forever. It is a receipt fragment, not evidence.
        stale = self.db.execute("SELECT source FROM records INDEXED BY records_quarantined WHERE error='unknown_source' AND source IN ('wazuh','wazuh-archive')").fetchall()
        if stale:
            with self.db:
                self.db.execute("DELETE FROM records WHERE error='unknown_source' AND source IN ('wazuh','wazuh-archive')")
                for (source,) in stale: self.drop_fragment(source)
        self.db.execute('CREATE INDEX IF NOT EXISTS events_indexing ON events(indexed,confirmed)')
        self.db.execute('CREATE INDEX IF NOT EXISTS events_export_producer ON events(producer,observed) WHERE confirmed IS NOT NULL AND indexed IS NULL')
        self.db.execute('CREATE INDEX IF NOT EXISTS events_export_time ON events(observed) WHERE confirmed IS NOT NULL AND indexed IS NULL')

    @contextmanager
    def transaction(self):
        with self.db:
            yield

    def ingest(self, source, source_id, position, raw, observed=None):
        observed = observed or now()
        ref = "xoc-evidence:" + hashlib.sha256(canonical([source_id, position])).hexdigest()
        digest = hashlib.sha256(raw).hexdigest()
        existing = self.db.execute("SELECT sha256 FROM records WHERE ref=?", (ref,)).fetchone()
        if existing:
            if existing[0] != digest:
                raise XocError("evidence_conflict", "An existing evidence reference has different bytes.")
            return ref
        from .retention import check_write
        check_write(self)
        error, events = None, []
        try:
            events = normalize(source, raw, Context(*self.identity, source_id, ref, observed))
        except XocError as exc:
            error = exc.code
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            error = "invalid_event"
        self.db.execute("INSERT INTO records(ref,source,observed,sha256,raw,error,source_id) VALUES (?,?,?,?,?,?,?)", (ref, source, observed, digest, raw, error, source_id))
        for event in events:
            self.db.execute("INSERT INTO events(id,ref,producer,observed,event) VALUES (?,?,?,?,?)",
                            (event["event_id"], ref, source, observed, canonical(event).decode()))
        # Agent activity (C1 v0.3) and facility events (C1 v0.4) have no Wazuh decoder; they stay
        # normalized C1 records.
        if error is None and source not in ('xoc-agent', 'xoc-facility') and self.cursor('native-input-enabled'):
            from .native_input import register
            register(self, ref, source, raw, events, observed)
        return ref

    def cursor(self, name):
        row = self.db.execute("SELECT value FROM cursors WHERE name=?", (name,)).fetchone()
        return json.loads(row[0]) if row else None

    def set_cursor(self, name, value):
        self.db.execute("INSERT OR REPLACE INTO cursors VALUES (?,?)", (name, json.dumps(value)))

    HEALTH_REFRESH = 20      # seconds; status() treats a check older than 60 s as stale

    def health(self, source, status):
        # Every write is a commit (fsync). The collector reports ~25 sources per loop, so on slow
        # disks unchanged statuses are refreshed at most every HEALTH_REFRESH seconds.
        seen = self.__dict__.setdefault('_health_seen', {})
        previous = seen.get(source)
        if previous and previous[0] == status and time.monotonic() - previous[1] < self.HEALTH_REFRESH:
            return
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO health VALUES (?,?,?)", (source, now(), status))
        seen[source] = (status, time.monotonic())

    def drop_fragment(self, source):
        """Count an unterminated Manager output tail that was discarded.

        Manager alerts and archives are receipts for evidence already stored here. A
        tail cut off by a restore cannot be parsed; the event it would have confirmed
        stays pending and is re-sent, so a real loss shows in the pending counters.
        """
        value = self.cursor('analysis-fragments') or {}
        value[source] = value.get(source, 0) + 1
        value['last'] = now()
        self.set_cursor('analysis-fragments', value)

    def processing_error(self, source, raw, code):
        from .retention import check_write
        ident = hashlib.sha256(canonical([source, code])+raw).hexdigest()
        if self.db.execute('SELECT 1 FROM processing_errors WHERE id=?',(ident,)).fetchone():return
        check_write(self, analysis=True)
        self.db.execute('INSERT OR IGNORE INTO processing_errors VALUES (?,?,?,?,?)',(ident,now(),source,code,raw))

    def pending(self, limit=4096):
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
        if limit<1:return []
        # Reserve a quarter for fresh observations during recovery, while the
        # remaining slots drain oldest evidence. Neither stream can starve.
        query="SELECT id,event FROM events INDEXED BY events_delivery_time WHERE confirmed IS NULL AND (sent IS NULL OR sent<?) ORDER BY observed {} LIMIT ?"
        recent=[]
        for source in SOURCES:
            recent.extend(self.db.execute('SELECT id,event FROM events INDEXED BY events_delivery_producer WHERE producer=? AND confirmed IS NULL AND (sent IS NULL OR sent<?) ORDER BY observed DESC LIMIT ?', (source,cutoff,max(1,limit//32))).fetchall())
        oldest=self.db.execute(query.format('ASC'),(cutoff,limit)).fetchall()
        result=[];seen=set()
        for row in [*recent,*oldest]:
            if row['id'] not in seen:result.append(row);seen.add(row['id'])
            if len(result)==limit:break
        return result

    def confirm(self, alert):
        # Raw-source alerts may themselves contain user-supplied event_id keys.
        # They cannot acknowledge or invalidate the separate C1 outbox.
        if alert.get('agent', {}).get('id') != '000' or alert.get('location') != 'xoc-c1' or not str(alert.get('rule', {}).get('id', '')).startswith('110'):
            return
        data = alert.get("data", {})
        if not isinstance(data, dict) or not isinstance(data.get("event_id"), str):
            return
        rule = str(alert.get("rule", {}).get("id", ""))
        row = self.db.execute("SELECT event FROM events WHERE id=?", (data["event_id"],)).fetchone()
        if not row:
            return
        expected = json.loads(row[0])
        if data.get("producer") != expected["producer"] or data.get("evidence", {}).get("sha256") != expected["evidence"]["sha256"]:
            raise XocError("siem_mismatch", "Wazuh decoded fields differ from the stored C1 event.")
        self.db.execute("UPDATE events SET confirmed=COALESCE(confirmed,?), rule_id=? WHERE id=?", (now(), rule, data["event_id"]))

    def query(self, producer=None, limit=20, confirmed=False):
        where, args = [], []
        if producer:
            where.append("producer=?"); args.append(producer)
        if confirmed:
            where.append("confirmed IS NOT NULL")
        clause = " WHERE " + " AND ".join(where) if where else ""
        rows = self.db.execute("SELECT event,confirmed,rule_id FROM events" + clause + " ORDER BY observed DESC,id LIMIT ?", (*args, max(1, min(limit, 1000))))
        return [{"event": json.loads(r[0]), "wazuh_confirmed_at": r[1], "wazuh_rule_id": r[2]} for r in rows]

    def index_batch(self, native=False, limit=4096):
        table, fields, where = ('wazuh_alerts', 'id,observed,raw,document,annotation', 'indexed IS NULL') if native else ('events', 'id,event,observed,confirmed,rule_id', 'confirmed IS NOT NULL AND indexed IS NULL')
        index = 'native_alerts_pending' if native else 'events_export_time'
        query = f'SELECT {fields} FROM {table} INDEXED BY {index} WHERE {where} ORDER BY observed {{}} LIMIT ?'
        if native:
            # External agents and stock detections must not be crowded out by
            # high-rate C1/Sysmon observations during archive recovery.
            recent = self.db.execute(f'SELECT {fields} FROM wazuh_alerts WHERE indexed IS NULL AND event_id IS NULL ORDER BY observed DESC LIMIT ?', (max(1,limit//8),)).fetchall()
            recent += self.db.execute(query.format('DESC'), (max(1,limit//8),)).fetchall()
        else:
            recent=[]
            for source in SOURCES:
                recent.extend(self.db.execute(f'SELECT {fields} FROM events INDEXED BY events_export_producer WHERE producer=? AND {where} ORDER BY observed DESC LIMIT ?', (source,max(1,limit//32))).fetchall())
        oldest = self.db.execute(query.format('ASC'), (limit,)).fetchall()
        result = []; seen = set()
        for row in [*recent, *oldest]:
            if row['id'] in seen: continue
            result.append(row); seen.add(row['id'])
            if len(result)==limit: break
        return result

    def retry(self, source=None):
        rows = self.db.execute('SELECT * FROM records WHERE error IS NOT NULL AND source_id IS NOT NULL AND (? IS NULL OR source=?) LIMIT 10000', (source, source)).fetchall()
        recovered = 0
        for row in rows:
            try:
                ctx = Context(*self.identity, row['source_id'], row['ref'], row['observed'])
                events = normalize(row['source'], row['raw'], ctx)
            except XocError:
                continue
            with self.transaction():
                for event in events:
                    self.db.execute('INSERT OR IGNORE INTO events(id,ref,producer,observed,event) VALUES (?,?,?,?,?)',
                                    (event['event_id'], row['ref'], row['source'], row['observed'], canonical(event).decode()))
                if self.cursor('native-input-enabled') and not self.db.execute('SELECT 1 FROM native_inputs WHERE ref=?',(row['ref'],)).fetchone():
                    from .native_input import register
                    register(self,row['ref'],row['source'],row['raw'],events,row['observed'])
                self.db.execute('UPDATE records SET error=NULL WHERE ref=?', (row['ref'],))
            recovered += 1
        return {'examined': len(rows), 'recovered': recovered}

    def status(self):
        result = {"sources": [dict(r) for r in self.db.execute("SELECT * FROM health ORDER BY source")],
                "counts": [dict(r) for r in self.db.execute("SELECT producer,COUNT(*) AS events,COUNT(confirmed) AS decoded FROM events GROUP BY producer")],
                "quarantined": self.db.execute("SELECT COUNT(*) FROM records WHERE error IS NOT NULL").fetchone()[0],
                "pending": self.db.execute("SELECT COUNT(*) FROM events WHERE confirmed IS NULL").fetchone()[0]}
        oldest = self.db.execute('SELECT MIN(observed) FROM events WHERE confirmed IS NULL').fetchone()[0]
        current = datetime.now(timezone.utc)
        result['oldest_pending_seconds'] = max(0, int((current - datetime.fromisoformat(oldest.replace('Z', '+00:00'))).total_seconds())) if oldest else 0
        journal = self.cursor('sysmon-journal') or {}
        result['sysmon_source_lag_seconds'] = max(0, int(current.timestamp() - journal['source_time'])) if journal.get('source_time') else None
        healthy = result['sources'] and all(r['status'] in ('ready', 'awaiting-file') and
            (current - datetime.fromisoformat(r['checked'].replace('Z', '+00:00'))).total_seconds() < (600 if r['source']=='retention' else 60) for r in result['sources'])
        result['status'] = 'ready' if healthy and not result['quarantined'] and result['oldest_pending_seconds'] < 120 else 'degraded'
        if self.cursor('native-input-enabled'):
            row=self.db.execute('SELECT COUNT(*),MIN(observed),SUM(error IS NOT NULL) FROM native_inputs WHERE confirmed IS NULL').fetchone()
            result['native_input_pending']=row[0]
            result['native_input_errors']=row[2] or 0
            result['oldest_native_input_pending_seconds']=max(0,int((current-datetime.fromisoformat(row[1].replace('Z','+00:00'))).total_seconds())) if row[1] else 0
            if result['native_input_errors'] or result['oldest_native_input_pending_seconds']>=120:result['status']='degraded'
        if self.cursor('indexer-enabled'):
            row=self.db.execute('SELECT COUNT(*),MIN(observed) FROM events WHERE confirmed IS NOT NULL AND indexed IS NULL').fetchone()
            result['index_pending']=row[0]
            result['oldest_index_pending_seconds']=max(0,int((current-datetime.fromisoformat(row[1].replace('Z','+00:00'))).total_seconds())) if row[1] else 0
            if result['oldest_index_pending_seconds']>=120: result['status']='degraded'
            row=self.db.execute('SELECT COUNT(*),MIN(observed) FROM wazuh_alerts WHERE indexed IS NULL').fetchone()
            result['native_alerts_pending']=row[0]
            if row[1] and (current-datetime.fromisoformat(row[1].replace('Z','+00:00'))).total_seconds()>=120:result['status']='degraded'
        from .retention import usage
        result['analysis_quarantined'] = self.db.execute('SELECT COUNT(*) FROM processing_errors').fetchone()[0]
        result['analysis_fragments_dropped'] = self.cursor('analysis-fragments') or {}
        if result['analysis_quarantined']: result['status'] = 'degraded'
        result['storage'] = {**usage(self), 'policy': self.policy}
        if result['storage']['used_bytes'] >= self.policy['ingest_bytes'] or result['storage']['filesystem_free_bytes'] < self.policy['reserve_bytes']:
            result['status'] = 'degraded'
        return result

    def prune(self, days=None, budget=None, batch=64):
        """Delete expired, fully handled rows; return True when none remain.

        Keys are content hashes, so each deleted row touches index pages
        scattered over the whole file. With a cold page cache (after an image
        build or a reboot) one unbounded pass took minutes and stalled the
        collector loop that calls it. With ``budget`` (seconds) the work is
        done in small committed batches and stops at the deadline; the caller
        continues on its next loop.
        """
        deadline = None if budget is None else time.monotonic() + budget
        days = self.policy['days'] if days is None else days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        enabled = int(bool(self.cursor('indexer-enabled')))
        tables = [
            ('events', "observed<? AND confirmed IS NOT NULL AND (?=0 OR indexed IS NOT NULL) AND NOT EXISTS (SELECT 1 FROM native_inputs n WHERE n.ref=events.ref AND n.confirmed IS NULL) AND (?=0 OR NOT EXISTS (SELECT 1 FROM wazuh_alerts a WHERE a.event_id=events.id AND a.indexed IS NULL))", (cutoff, enabled, enabled)),
            ('records', "observed<? AND ref NOT IN (SELECT ref FROM events) AND NOT EXISTS (SELECT 1 FROM native_inputs n WHERE n.ref=records.ref AND n.confirmed IS NULL)", (cutoff,)),
            ('wazuh_alerts', 'observed<? AND (?=0 OR indexed IS NOT NULL)', (cutoff, enabled)),
            ('processing_errors', 'observed<?', (cutoff,)),
        ]
        # Resume at the table a deadline interrupted and visit every table once
        # per pass. Starting each slice at the first table let it spend the
        # whole budget on newly expired rows while the last table never ran.
        start = getattr(self, '_prune_resume', 0)
        self.prune_deleted = 0      # rows removed by this call: an unfinished pass that removes rows is still working
        for index in [*range(start, len(tables)), *range(start)]:
            table, condition, params = tables[index]
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    self._prune_resume = index
                    return False
                with self.db:
                    deleted = self.db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {condition} LIMIT ?)', (*params, batch)).rowcount
                self.prune_deleted += deleted
                if deleted < batch:
                    break
        self._prune_resume = 0
        return self.compact(deadline=deadline)

    def compact(self, max_pages=65536, deadline=None, step=2048):
        """Return free pages to the filesystem in bounded steps; True when none are left.

        Without this the file stays at its high-water mark: a 7 GB store held
        38 GB on disk, which every pre-install backup then had to copy.
        """
        if self.db.execute('PRAGMA auto_vacuum').fetchone()[0] != 2:
            return True
        remaining = int(max_pages)
        free = self.db.execute('PRAGMA freelist_count').fetchone()[0]
        while free and remaining > 0:
            if deadline is not None and time.monotonic() >= deadline:
                break
            pages = min(free, remaining, step if deadline is not None else remaining)
            self.db.execute(f'PRAGMA incremental_vacuum({pages})').fetchall()
            remaining -= pages
            free = self.db.execute('PRAGMA freelist_count').fetchone()[0]
        self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)' if deadline is None or not free else 'PRAGMA wal_checkpoint(PASSIVE)')
        return not free
