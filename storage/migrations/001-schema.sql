CREATE TABLE certificates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT UNIQUE NOT NULL,
	certificate BLOB NOT NULL,
	private_key BLOB NOT NULL,
	issuer_cert BLOB,
	not_before DATETIME NOT NULL,
	not_after DATETIME NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_certificates_domain ON certificates(domain);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);

CREATE TABLE le_credentials (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT UNIQUE NOT NULL,
	key_type TEXT NOT NULL,
	key BLOB NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
