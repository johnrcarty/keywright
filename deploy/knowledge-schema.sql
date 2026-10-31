-- Run once in a dedicated knowledge index database as its owner.
-- The runtime user needs SELECT/INSERT/DELETE on this table, not extension/DDL privileges.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS knowledge_search_chunks (
    id text PRIMARY KEY,
    collection text NOT NULL,
    model text NOT NULL,
    title text NOT NULL,
    body text NOT NULL,
    embedding vector NOT NULL,
    search tsvector GENERATED ALWAYS AS
        (to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(body, ''))) STORED
);
CREATE INDEX IF NOT EXISTS knowledge_search_collection ON knowledge_search_chunks (collection, model);
CREATE INDEX IF NOT EXISTS knowledge_search_text ON knowledge_search_chunks USING gin (search);
-- Exact cosine ranking is deliberate for small collections and arbitrary embedding dimensions.
-- Add a dimension-specific ANN index only after measuring filtered recall and query latency.
