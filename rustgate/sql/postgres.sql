-- RustGate durable journal for PostgreSQL 14+.
--
-- One append-only, hash-chained table holds every state change of a RustGate
-- instance ("stream"). The database itself enforces the WORM properties:
--   * UPDATE, DELETE and TRUNCATE are rejected by triggers;
--   * each row must link to the previous row's hash (no gaps, no forks);
--   * (stream, seq) and (stream, entry_hash) are unique, so a concurrent
--     second writer fails instead of forking the chain.
-- RustGate additionally re-verifies every hash when it loads the stream, so a
-- privileged user who disables the triggers still cannot tamper undetected.
--
-- Install this file as the owner/migration role (PostgresJournal::migrate).
-- Run the application as a role that holds only INSERT and SELECT on this
-- table; it never needs DDL, and without ownership it cannot disable the
-- triggers. E.g.:
--   REVOKE ALL ON rustgate_journal FROM PUBLIC;
--   GRANT SELECT, INSERT ON rustgate_journal TO rustgate_app;

CREATE TABLE IF NOT EXISTS rustgate_journal (
    stream      TEXT        NOT NULL,
    seq         BIGINT      NOT NULL CHECK (seq >= 0),
    prev_hash   CHAR(64)    NOT NULL,
    entry_hash  CHAR(64)    NOT NULL,
    kind        TEXT        NOT NULL,
    -- Exact bytes as written; the JSONB copy exists for querying only.
    entry       TEXT        NOT NULL,
    entry_json  JSONB       GENERATED ALWAYS AS (entry::jsonb) STORED,
    written_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (stream, seq),
    -- Per stream: RustGate is deterministic, so two streams that saw the
    -- same inputs legitimately produce identical entry hashes.
    UNIQUE (stream, entry_hash)
);

CREATE INDEX IF NOT EXISTS rustgate_journal_kind ON rustgate_journal (stream, kind);

CREATE OR REPLACE FUNCTION rustgate_journal_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'rustgate_journal is append-only: % rejected', TG_OP;
END
$$;

CREATE OR REPLACE FUNCTION rustgate_journal_check_link() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    expected CHAR(64);
BEGIN
    IF NEW.seq = 0 THEN
        expected := repeat('0', 64);
    ELSE
        SELECT entry_hash INTO expected
          FROM rustgate_journal
         WHERE stream = NEW.stream AND seq = NEW.seq - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'rustgate_journal: sequence gap before seq % in stream %', NEW.seq, NEW.stream;
        END IF;
    END IF;
    IF NEW.prev_hash <> expected THEN
        RAISE EXCEPTION 'rustgate_journal: seq % does not link to its predecessor', NEW.seq;
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE TRIGGER rustgate_journal_no_update_delete
    BEFORE UPDATE OR DELETE ON rustgate_journal
    FOR EACH ROW EXECUTE FUNCTION rustgate_journal_reject_mutation();

CREATE OR REPLACE TRIGGER rustgate_journal_no_truncate
    BEFORE TRUNCATE ON rustgate_journal
    FOR EACH STATEMENT EXECUTE FUNCTION rustgate_journal_reject_mutation();

CREATE OR REPLACE TRIGGER rustgate_journal_link
    BEFORE INSERT ON rustgate_journal
    FOR EACH ROW EXECUTE FUNCTION rustgate_journal_check_link();
