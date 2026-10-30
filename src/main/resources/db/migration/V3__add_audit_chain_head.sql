CREATE TABLE audit_chain_head (
    singleton BOOLEAN DEFAULT TRUE NOT NULL CHECK (singleton),
    last_event_id BIGINT,
    last_hash CHAR(64),
    CONSTRAINT audit_chain_head_pk PRIMARY KEY (singleton)
);
INSERT INTO audit_chain_head (singleton, last_event_id, last_hash) VALUES (TRUE, NULL, NULL);
