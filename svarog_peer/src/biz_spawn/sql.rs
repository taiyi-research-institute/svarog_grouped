pub const SQL_CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS peer_session (
    session_id CHAR(32) NOT NULL,
    member_id INT NOT NULL,
    member_name TEXT NOT NULL,
    expire_at INT NOT NULL,
    fruit BLOB DEFAULT NULL,
    exception TEXT DEFAULT NULL,
    primary key (session_id, member_id)
);
"#;

pub const SQL_INSERT_SESSION_FRUIT: &str = r#"
INSERT INTO peer_session
    (session_id, member_id, member_name, expire_at, fruit, exception)
VALUES (?, ?, ?, ?, ?, ?)
"#;

pub const SQL_SELECT_SESSION_FRUIT: &str = r#"
SELECT * FROM peer_session
WHERE session_id = ? AND member_name = ?
ORDER BY member_id ASC
"#;
