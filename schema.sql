CREATE TABLE IF NOT EXISTS oidc_client (
    client_id VARCHAR(65),
    client_secret TEXT,
    owner_id VARCHAR(50),
    scope TEXT,
    redirect_uri TEXT,
    PRIMARY KEY (client_id)
);

CREATE TABLE IF NOT EXISTS oidc_req_tmp (
    oidc_state_hash TEXT,
    oidc_state TEXT,
    client_id VARCHAR(50),
    redirect_uri TEXT,
    code VARCHAR(50),
    datr TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (oidc_state_hash),
    FOREIGN KEY(client_id) REFERENCES oidc_client(client_id) ON DELETE CASCADE
);

--INSERT IGNORE INTO oidc_client (client_id,client_secret,owner_id,scope,redirect_uri) VALUES (UUID(),MD5(RAND()),"0","identify email guilds guilds.members.read","https://");