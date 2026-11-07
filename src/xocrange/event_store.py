"""Private, transactional evidence/event store and durable Wazuh outbox."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from .documents import canonical
from .errors import XocError
from .events import Context, normalize


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Store:
    def __init__(self, directory):
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
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS records (
          ref TEXT PRIMARY KEY, source TEXT NOT NULL, observed TEXT NOT NULL,
          sha256 TEXT NOT NULL, raw BLOB NOT NULL, error TEXT);
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, ref TEXT NOT NULL REFERENCES records(ref), producer TEXT NOT NULL,
          observed TEXT NOT NULL, event TEXT NOT NULL, sent TEXT, confirmed TEXT, rule_id TEXT);
        CREATE INDEX IF NOT EXISTS events_producer_time ON events(producer, observed);
        CREATE INDEX IF NOT EXISTS events_pending ON events(confirmed, sent);
        CREATE TABLE IF NOT EXISTS cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS health (source TEXT PRIMARY KEY, checked TEXT NOT NULL, status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS wazuh_alerts (
          id TEXT PRIMARY KEY, observed TEXT NOT NULL, raw BLOB NOT NULL, sha256 TEXT NOT NULL,
          document TEXT NOT NULL, event_id TEXT, indexed TEXT);
        CREATE INDEX IF NOT EXISTS native_alerts_pending ON wazuh_alerts(indexed,observed);
        ''')
        if 'source_id' not in {r[1] for r in self.db.execute('PRAGMA table_info(records)')}:
            self.db.execute('ALTER TABLE records ADD COLUMN source_id TEXT')
            self.db.commit()
        if 'indexed' not in {r[1] for r in self.db.execute('PRAGMA table_info(events)')}:
            self.db.execute('ALTER TABLE events ADD COLUMN indexed TEXT')
            self.db.commit()
        self.db.execute('CREATE INDEX IF NOT EXISTS events_indexing ON events(indexed,confirmed)')

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
        pages = self.db.execute("PRAGMA page_count").fetchone()[0] - self.db.execute("PRAGMA freelist_count").fetchone()[0]
        size = pages * self.db.execute("PRAGMA page_size").fetchone()[0]
        if size > 4 * 1024**3:
            raise XocError("store_full", "Evidence storage reached its 4 GiB budget; ingestion is paused.")
        error, events = None, []
        try:
            events = normalize(source, raw, Context("community", "local", source_id, ref, observed))
        except XocError as exc:
            error = exc.code
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            error = "invalid_event"
        self.db.execute("INSERT INTO records(ref,source,observed,sha256,raw,error,source_id) VALUES (?,?,?,?,?,?,?)", (ref, source, observed, digest, raw, error, source_id))
        for event in events:
            self.db.execute("INSERT INTO events(id,ref,producer,observed,event) VALUES (?,?,?,?,?)",
                            (event["event_id"], ref, source, observed, canonical(event).decode()))
        return ref

    def cursor(self, name):
        row = self.db.execute("SELECT value FROM cursors WHERE name=?", (name,)).fetchone()
        return json.loads(row[0]) if row else None

    def set_cursor(self, name, value):
        self.db.execute("INSERT OR REPLACE INTO cursors VALUES (?,?)", (name, json.dumps(value)))

    def health(self, source, status):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO health VALUES (?,?,?)", (source, now(), status))

    def pending(self, limit=4096):
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
        if limit<1:return []
        # Reserve a quarter for fresh observations during recovery, while the
        # remaining slots drain oldest evidence. Neither stream can starve.
        query="SELECT id,event FROM events WHERE confirmed IS NULL AND (sent IS NULL OR sent<?) ORDER BY observed {} LIMIT ?"
        recent=self.db.execute(query.format('DESC'),(cutoff,max(1,limit//4))).fetchall()
        oldest=self.db.execute(query.format('ASC'),(cutoff,limit)).fetchall()
        result=[];seen=set()
        for row in [*recent,*oldest]:
            if row['id'] not in seen:result.append(row);seen.add(row['id'])
            if len(result)==limit:break
        return result

    def confirm(self, alert):
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
        if not rule.startswith("110"):
            # Native rules can also match JSON carrying an event_id. Preserve
            # that alert separately, but never acknowledge C1 with a native rule.
            return
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

    def retry(self, source=None):
        rows = self.db.execute('SELECT * FROM records WHERE error IS NOT NULL AND source_id IS NOT NULL AND (? IS NULL OR source=?) LIMIT 10000', (source, source)).fetchall()
        recovered = 0
        for row in rows:
            try:
                ctx = Context('community', 'local', row['source_id'], row['ref'], row['observed'])
                events = normalize(row['source'], row['raw'], ctx)
            except XocError:
                continue
            with self.transaction():
                for event in events:
                    self.db.execute('INSERT OR IGNORE INTO events(id,ref,producer,observed,event) VALUES (?,?,?,?,?)',
                                    (event['event_id'], row['ref'], row['source'], row['observed'], canonical(event).decode()))
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
            (current - datetime.fromisoformat(r['checked'].replace('Z', '+00:00'))).total_seconds() < 60 for r in result['sources'])
        result['status'] = 'ready' if healthy and not result['quarantined'] and result['oldest_pending_seconds'] < 120 else 'degraded'
        if self.cursor('indexer-enabled'):
            row=self.db.execute('SELECT COUNT(*),MIN(observed) FROM events WHERE confirmed IS NOT NULL AND indexed IS NULL').fetchone()
            result['index_pending']=row[0]
            result['oldest_index_pending_seconds']=max(0,int((current-datetime.fromisoformat(row[1].replace('Z','+00:00'))).total_seconds())) if row[1] else 0
            if result['oldest_index_pending_seconds']>=120: result['status']='degraded'
            row=self.db.execute('SELECT COUNT(*),MIN(observed) FROM wazuh_alerts WHERE indexed IS NULL').fetchone()
            result['native_alerts_pending']=row[0]
            if row[1] and (current-datetime.fromisoformat(row[1].replace('Z','+00:00'))).total_seconds()>=120:result['status']='degraded'
        return result

    def prune(self, days=7):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        with self.db:
            self.db.execute("DELETE FROM events WHERE observed<? AND confirmed IS NOT NULL AND (?=0 OR indexed IS NOT NULL)", (cutoff,int(bool(self.cursor('indexer-enabled')))))
            self.db.execute("DELETE FROM records WHERE observed<? AND ref NOT IN (SELECT ref FROM events)", (cutoff,))
            self.db.execute('DELETE FROM wazuh_alerts WHERE observed<? AND (?=0 OR indexed IS NOT NULL)',(cutoff,int(bool(self.cursor('indexer-enabled')))))
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
