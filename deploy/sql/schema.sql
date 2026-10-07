-- Durable incident store for multi-replica analyzers.
-- MemoryStore is the default. Point replicas at Postgres when an incident
-- must survive a process restart. Shard ownership stays in the hash ring;
-- this table is the system of record.

CREATE TABLE IF NOT EXISTS incidents (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    fault           TEXT NOT NULL,
    title           TEXT NOT NULL,
    summary         TEXT NOT NULL,
    root_cause      TEXT NOT NULL,
    recommendations JSONB NOT NULL DEFAULT '[]',
    confidence      DOUBLE PRECISION NOT NULL,
    platform        TEXT NOT NULL,
    cluster         TEXT,
    node            TEXT,
    namespace       TEXT,
    pod             TEXT,
    vm_id           TEXT,
    evidence        JSONB NOT NULL DEFAULT '[]',
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    resolved_at     TIMESTAMPTZ,
    windows         INTEGER NOT NULL,
    source          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_open_last_seen
    ON incidents (last_seen DESC)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS incidents_entity
    ON incidents (platform, cluster, namespace, pod, node);

-- Signals are retained only for the explanation window. A wide column store
-- (ClickHouse) is the right place past a few thousand nodes; this table is
-- the operational record of what an incident cited.
CREATE TABLE IF NOT EXISTS signals (
    ts          TIMESTAMPTZ NOT NULL,
    node        TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    name        TEXT NOT NULL,
    value       DOUBLE PRECISION NOT NULL,
    source      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS signals_entity_ts ON signals (entity_key, ts DESC);
