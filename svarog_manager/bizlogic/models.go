package bizlogic

type MpcSession struct {
	SessionId          string `gorm:"primarykey;size:32"`
	SessionType        string `gorm:"size:32"`
	KeyQuorum          uint64
	ReshareKeyQuorum   uint64
	ExpireBeforeFinish int64
	ExpireAfterFinish  int64
	DerivePath         string `gorm:"size:256"`
	MarshalledTxHashes []byte
	Result             []byte
	DataCache          []byte
	TerminationHash    []byte
	Whistle            string `gorm:"default ''"`
}

type MpcGroup struct {
	SessionId   string `gorm:"primarykey;size:32"`
	GroupId     uint64 `gorm:"primarykey"`
	GroupName   string
	GroupQuorum uint64
	IsReshare   bool
	MpcSession  MpcSession `gorm:"constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
}

type MpcMember struct {
	SessionId    string `gorm:"primarykey;size:32"`
	MemberId     uint64 `gorm:"primarykey"`
	GroupId      uint64
	MemberName   string
	IsAttending  bool
	IsTerminated bool
	MpcGroup     MpcGroup `gorm:"constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
}

type MpcMessage struct {
	SessionId   string `gorm:"primarykey;size:32"`
	MemberIdSrc uint64 `gorm:"primarykey"`
	MemberIdDst uint64 `gorm:"primarykey"`
	Purpose     string `gorm:"primarykey;size:128"`
	Body        []byte

	// It worth to trade some consistency, i.e. no foreign key of MemberId, for simpler server code.
	// If the data is inconsistent, the mpc clients will fail.
	MpcSession MpcSession `gorm:"constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
}
