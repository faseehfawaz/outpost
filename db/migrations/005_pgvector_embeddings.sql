-- 005_pgvector_embeddings.sql
CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE kits ADD COLUMN IF NOT EXISTS embedding vector(384);
ALTER TABLE urls ADD COLUMN IF NOT EXISTS embedding vector(384);

CREATE INDEX IF NOT EXISTS idx_kits_embedding ON kits USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_urls_embedding ON urls USING hnsw (embedding vector_cosine_ops);
