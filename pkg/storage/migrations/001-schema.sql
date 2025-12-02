-- SQL Convention: Each table has a single concrete Data JSON column, all other columns are generated from it.

CREATE TABLE certificates (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain     TEXT NOT NULL AS (data->>'domain') STORED UNIQUE,
	not_after  INTEGER NOT NULL AS (unixepoch(data->>'not_after')) STORED,
	data       JSON NOT NULL
);

CREATE INDEX idx_certificates_domain ON certificates(domain);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);

CREATE TABLE le_credentials (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	email      TEXT NOT NULL AS (data->>'email') STORED UNIQUE,
	data       JSON NOT NULL
);
