package bizlogic

const sql_ddl = `
CREATE TABLE IF NOT EXISTS mpc_sessions (
	session_id           TEXT PRIMARY KEY,
	session_type         TEXT NOT NULL,
	key_quorum           INT NOT NULL,
	reshare_key_quorum   INT NOT NULL,
	expire_before_finish INT NOT NULL,
	expire_after_finish  INT NOT NULL,
	marshalled_tx_hashes BLOB NOT NULL,
	result               BLOB NOT NULL,
	termination_hash     BLOB NOT NULL,
	whistle              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mpc_groups (
	session_id   TEXT NOT NULL,
	group_id     INT NOT NULL,
	group_name   TEXT NOT NULL,
	group_quorum INT NOT NULL,
	is_reshare   INT NOT NULL,
	PRIMARY KEY (session_id, group_id),
	FOREIGN KEY (session_id) REFERENCES mpc_sessions (session_id)
		ON UPDATE RESTRICT ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mpc_members (
	session_id    TEXT NOT NULL,
	member_id     INT NOT NULL,
	group_id      INT NOT NULL,
	member_name   TEXT NOT NULL,
	is_attending  INT NOT NULL,
	is_terminated INT NOT NULL,
	PRIMARY KEY (session_id, member_id),
	FOREIGN KEY (session_id, group_id) REFERENCES mpc_groups (session_id, group_id)
		ON UPDATE RESTRICT ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mpc_messages (
	session_id   TEXT NOT NULL,
	member_id_src INT NOT NULL,
	member_id_dst INT NOT NULL,
	purpose       TEXT NOT NULL,
	body          BLOB NOT NULL,
	PRIMARY KEY (session_id, member_id_src, member_id_dst, purpose),
	FOREIGN KEY (session_id) REFERENCES mpc_sessions (session_id)
		ON UPDATE RESTRICT ON DELETE CASCADE
);`

type MpcSession struct {
	SessionId          string `gorm:"primarykey;size:32"`
	SessionType        string `gorm:"size:32"`
	KeyQuorum          uint64
	ReshareKeyQuorum   uint64
	ExpireBeforeFinish int64
	ExpireAfterFinish  int64
	MarshalledTxHashes []byte
	Result             []byte
	TerminationHash    []byte
	Whistle            string `gorm:"default ''"`
}

type MpcGroup struct {
	SessionId   string `gorm:"primarykey;size:32"`
	GroupId     uint64 `gorm:"primarykey"`
	GroupName   string
	GroupQuorum uint64
	IsReshare   bool
	MpcSession  MpcSession `gorm:"foreignKey:SessionId;references:SessionId;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
}

type MpcMember struct {
	SessionId    string `gorm:"primarykey;size:32"`
	MemberId     uint64 `gorm:"primarykey"`
	GroupId      uint64
	MemberName   string
	IsAttending  bool
	IsTerminated bool
	MpcGroup     MpcGroup `gorm:"foreignKey:SessionId,GroupId;references:SessionId,GroupId;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
}

type MpcMessage struct {
	SessionId   string `gorm:"primarykey;size:32"`
	MemberIdSrc uint64 `gorm:"primarykey"`
	MemberIdDst uint64 `gorm:"primarykey"`
	Purpose     string `gorm:"primarykey;size:128"`
	Body        []byte

	// It worth to trade some consistency, i.e. no foreign key of MemberId, for simpler server code.
	// If the data is inconsistent, the mpc clients will fail.
	MpcSession MpcSession `gorm:"foreignKey:SessionId;references:SessionId;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
}
