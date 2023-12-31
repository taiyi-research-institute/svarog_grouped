package bizlogic

import (
	"context"
	"errors"
	"sort"
	"time"

	pb "svarog_manager/proto/gen"
	util "svarog_manager/util"

	proto "google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

func (srv *SessionManager) NewSession(
	ctx context.Context,
	req *pb.SessionConfig,
) (resp *pb.SessionConfig, err error) {
	db := srv.db

	{ // Validate the request
		assert_sestype := req.SessionType == "keygen" ||
			req.SessionType == "sign" ||
			req.SessionType == "reshare"
		if !assert_sestype {
			return nil, errors.New("Invalid session type")
		}

		if req.SessionType == "keygen" {
			_members := make(map[string]bool)
			_groups := make(map[string]bool)
			if req.KeyQuorum < 1 { // Key quorum is at least one.
				return nil, errors.New("Key quorum should be at least one")
			}
			for _, group := range req.Groups {
				if group.IsReshare { // No group is reshare.
					return nil, errors.New("Any keygen group should not reshare")
				}
				if _groups[group.GroupName] { // Every group is unique.
					return nil, errors.New("Every keygen group should be unique")
				}
				_groups[group.GroupName] = true
				_group_member_count := uint64(0)
				for _, member := range group.Members {
					if _members[member.MemberName] { // Every member is unique.
						return nil, errors.New("Every keygen member should be unique")
					}
					_members[member.MemberName] = true
					if !member.IsAttending { // Every member is attending.
						return nil, errors.New("Every keygen member should attend")
					}
					_group_member_count += 1
				}
				if group.GroupQuorum > _group_member_count {
					return nil, errors.New("Group quorum should not exceed the count of members")
				}
			}
			if len(_groups) < 1 { // At least one group.
				return nil, errors.New("At least one keygen group is required")
			}
			if len(_members) < 1 { // At least two members.
				return nil, errors.New("At lest one keygen member is required")
			}
			if req.KeyQuorum > uint64(len(_members)) {
				return nil, errors.New("Key quorum should not exceed the count of members")
			}
		} else if req.SessionType == "sign" {
			_cdd := make(map[string]bool)
			_groups := make(map[string]bool)
			_gq := make(map[string]uint64)
			_gatt := make(map[string]uint64)
			_katt := uint64(0)
			_kq := req.KeyQuorum
			if _kq < 1 {
				return nil, errors.New("Key quorum should be at least one")
			}
			for _, group := range req.Groups {
				if group.IsReshare { // No group is reshare.
					return nil, errors.New("Any sign group should not reshare")
				}
				if _groups[group.GroupName] { // Every group is unique.
					return nil, errors.New("Every sign group should be unique")
				}
				_groups[group.GroupName] = true
				_gq[group.GroupName] = group.GroupQuorum
				for _, member := range group.Members {
					if _cdd[member.MemberName] { // Every member is unique.
						return nil, errors.New("Every sign candidate should be unique")
					}
					_cdd[member.MemberName] = true
					if member.IsAttending {
						_gatt[group.GroupName] += 1
						_katt += 1
					}
				}
			}
			if len(_groups) < 1 { // At least one group.
				return nil, errors.New("At least one sign group is required")
			}
			if len(_cdd) < 1 { // At least two members.
				return nil, errors.New("At lest one sign candidate is required")
			}
			if _katt < _kq { // Key quorum is satisfied.
				return nil, errors.New("Key quorum is not satisfied")
			}
			for _, group := range req.Groups {
				if _gatt[group.GroupName] < _gq[group.GroupName] {
					return nil, errors.New("Group quorum is not satisfied")
				}
			}
		} else {
			{ // Validate like sign
				_cdd := make(map[string]bool)
				_groups := make(map[string]bool)
				_gq := make(map[string]uint64)
				_gatt := make(map[string]uint64)
				_katt := uint64(0)
				_kq := req.KeyQuorum
				for _, group := range req.Groups {
					if _groups[group.GroupName] { // Every group is unique.
						return nil, errors.New("Every non-reshare group should be unique")
					}
					_groups[group.GroupName] = true
					_gq[group.GroupName] = group.GroupQuorum
					for _, member := range group.Members {
						if _cdd[member.MemberName] { // Every member is unique.
							return nil, errors.New("Every non-reshare candidate should be unique")
						}
						_cdd[member.MemberName] = true
						if member.IsAttending {
							_gatt[group.GroupName] += 1
							_katt += 1
						}
					}
				}
				if len(_groups) < 1 { // At least one group.
					return nil, errors.New("At least one non-reshare group is required")
				}
				if len(_cdd) < 1 { // At least two members.
					return nil, errors.New("At lest one non-reshare candidate is required")
				}
				if _katt < _kq { // Key quorum is satisfied.
					return nil, errors.New("Non-reshare key quorum is not satisfied")
				}
				for _, group := range req.Groups {
					if _gatt[group.GroupName] < _gq[group.GroupName] {
						return nil, errors.New("Non-reshare group quorum is not satisfied")
					}
				}
			}

			{ // Validate like keygen
				_members := make(map[string]bool)
				_groups := make(map[string]bool)
				_kq := req.ReshareKeyQuorum
				if _kq < 1 {
					return nil, errors.New("Reshare key quorum should be at least one")
				}
				for _, group := range req.Groups {
					if !group.IsReshare {
						continue
					}
					if _groups[group.GroupName] { // Every group is unique.
						return nil, errors.New("Every reshare group should be unique")
					}
					_groups[group.GroupName] = true
					_group_member_count := uint64(0)
					for _, member := range group.Members {
						if _members[member.MemberName] { // Every member is unique.
							return nil, errors.New("Every reshare member should be unique")
						}
						_members[member.MemberName] = true
						if !member.IsAttending { // Every member is attending.
							return nil, errors.New("Every reshare member should attend")
						}
						_group_member_count += 1
					}
					if group.GroupQuorum > _group_member_count {
						return nil, errors.New("Reshare group quorum should not exceed the count of members")
					}
				}
				if len(_groups) < 1 { // At least one group.
					return nil, errors.New("At least one reshare group is required")
				}
				if len(_members) < 1 { // At least one member.
					return nil, errors.New("At lest one reshare member is required")
				}
				if _kq > uint64(len(_members)) {
					return nil, errors.New("Reshare key quorum should not exceed the count of members")
				}
			}
		}
	}

	// Assign session_id if not provided
	if req.SessionId == "" {
		req.SessionId = util.Uuid()
	}

	{ // Assign member_id by sorting groups and members
		// sort groups by (IsReshare, GroupName)
		sort.SliceStable(req.Groups, func(i, j int) bool {
			reshare_lt := !req.Groups[i].IsReshare && req.Groups[j].IsReshare
			reshare_eq := req.Groups[i].IsReshare == req.Groups[j].IsReshare
			name_lt := req.Groups[i].GroupName < req.Groups[j].GroupName
			return reshare_lt || (reshare_eq && name_lt)
		})

		// assign group_id
		for i := range req.Groups {
			req.Groups[i].GroupId = uint64(i + 1)
		}

		// sort members by (GroupId, MemberName)
		for _, group := range req.Groups {
			sort.SliceStable(group.Members, func(i, j int) bool {
				name_lt := group.Members[i].MemberName < group.Members[j].MemberName
				return name_lt
			})
		}

		// assign member_id
		var member_id uint64 = 1
		for _, group := range req.Groups {
			for _, member := range group.Members {
				member.MemberId = member_id
				member_id++
			}
		}
	}

	{ // Save session to db
		if req.ExpireBeforeFinish == 0 {
			req.ExpireBeforeFinish = time.Now().Unix() + 1200
		}
		if req.ExpireAfterFinish == 0 {
			req.ExpireAfterFinish = time.Now().Unix() + 86400
		}
		new_session := MpcSession{
			SessionId:          req.SessionId,
			SessionType:        req.SessionType,
			KeyQuorum:          req.KeyQuorum,
			ReshareKeyQuorum:   req.ReshareKeyQuorum,
			ExpireBeforeFinish: req.ExpireBeforeFinish,
			ExpireAfterFinish:  req.ExpireAfterFinish,
			Result:             make([]byte, 0),
			TerminationHash:    make([]byte, 0),
			Whistle:            "",
		}
		if req.SessionType == "sign" {
			marshalled_tx_hashes, err := proto.Marshal(req.ToSign)
			if err != nil {
				srv.Error(err)
				return nil, err
			}
			new_session.MarshalledTxHashes = marshalled_tx_hashes
		} else {
			new_session.MarshalledTxHashes = make([]byte, 0)
		}

		err = db.Create(&new_session).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
	}

	// Save groups to db
	for _, group := range req.Groups {
		{
			new_group := MpcGroup{
				SessionId:   req.SessionId,
				GroupId:     group.GroupId,
				GroupName:   group.GroupName,
				GroupQuorum: group.GroupQuorum,
				IsReshare:   group.IsReshare,
			}
			err = db.Create(&new_group).Error
			if err != nil {
				srv.Error(err)
				return nil, err
			}
		}
	}

	// Save members to db
	for _, group := range req.Groups {
		for _, member := range group.Members {
			new_member := MpcMember{
				SessionId:    req.SessionId,
				MemberId:     member.MemberId,
				MemberName:   member.MemberName,
				IsAttending:  member.IsAttending,
				GroupId:      group.GroupId,
				IsTerminated: false,
			}
			err = db.Create(&new_member).Error
			if err != nil {
				srv.Error(err)
				return nil, err
			}
		}
	}

	resp = req
	return resp, nil
}

func (srv *SessionManager) TerminateSession(
	ctx context.Context,
	req *pb.SessionId,
) (resp *pb.Void, err error) {
	db := srv.db
	resp = &pb.Void{}

	err = db.Exec("DELETE FROM mpc_sessions WHERE session_id = ?", req.SessionId).Error
	if err != nil {
		srv.Error(err)
		return nil, err
	}

	return resp, nil
}

func (srv *SessionManager) GetSessionConfig(
	ctx context.Context,
	req *pb.SessionId,
) (resp *pb.SessionConfig, err error) {
	db := srv.db
	resp = &pb.SessionConfig{}

	var session *MpcSession
	{ // get session from db
		err = db.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
	}

	var ses_groups []*MpcGroup
	{ // get groups from db
		err = db.Where("session_id = ?", req.SessionId).
			Order("group_id ASC").
			Find(&ses_groups).
			Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
		if len(ses_groups) == 0 {
			srv.Errorw("Session is not properly created", "SessionId", req.SessionId)
			return nil, err
		}
	}

	// Fill "Groups" in response
	for _, ses_group := range ses_groups {
		resp.Groups = append(
			resp.Groups,
			&pb.Group{
				GroupName:   ses_group.GroupName,
				GroupId:     ses_group.GroupId,
				GroupQuorum: ses_group.GroupQuorum,
				IsReshare:   ses_group.IsReshare,
			},
		)
	}

	// Fill members of "Groups" in response
	for _, resp_group := range resp.Groups {
		var ses_members []*MpcMember
		err = db.Where("session_id = ? AND group_id = ?", req.SessionId, resp_group.GroupId).
			Order("member_id ASC").
			Find(&ses_members).
			Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
		for _, ses_member := range ses_members {
			resp_group.Members = append(
				resp_group.Members,
				&pb.Member{
					MemberName:  ses_member.MemberName,
					MemberId:    ses_member.MemberId,
					IsAttending: ses_member.IsAttending,
				},
			)
		}
	}

	{ // fill other session parameters
		resp.SessionId = session.SessionId
		resp.SessionType = session.SessionType
		resp.KeyQuorum = session.KeyQuorum
		resp.ReshareKeyQuorum = session.ReshareKeyQuorum
		resp.ExpireBeforeFinish = session.ExpireBeforeFinish
		resp.ExpireAfterFinish = session.ExpireAfterFinish
		resp.ToSign = &pb.ToSign{}
		err = proto.Unmarshal(session.MarshalledTxHashes, resp.ToSign)
		if err != nil {
			srv.Error(err)
			return nil, err
		}
	}

	return resp, nil
}

func (srv *SessionManager) GetSessionFruit(
	ctx context.Context,
	req *pb.SessionId,
) (resp *pb.SessionFruit, err error) {
	db := srv.db
	resp = &pb.SessionFruit{}

	// If a whistle is blown, return with error.
	var session *MpcSession
	{ // get session from db
		err = db.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		// If a whistle is blown, return with error.
		if session.Whistle != "" {
			srv.Debugw("Session is dangerous", "SessionId", req.SessionId)
			return nil, errors.New(session.Whistle)
		}
	}

	if len(session.Result) == 0 {
		resp.Value = nil
	} else {
		fruit := &pb.SessionFruit{}
		err = proto.Unmarshal(session.Result, fruit)
		if err != nil {
			srv.Error(err)
			return nil, err
		}
	}

	return resp, nil
}

func (srv *SessionManager) BlowWhistle(
	ctx context.Context,
	req *pb.Whistle,
) (resp *pb.Void, err error) {
	db := srv.db

	var session *MpcSession
	{ // Append req.Message to session.Whistle
		err = db.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		session.Whistle += req.Message
		err = db.Save(session).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
	}

	return resp, nil
}

func (srv *SessionManager) PostMessage(
	ctx context.Context,
	req *pb.Message,
) (resp *pb.Void, err error) {
	db := srv.db
	resp = &pb.Void{}

	// If a whistle is blown, return with error.
	var session *MpcSession
	{ // get session from db
		err = db.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		// If a whistle is blown, return with error.
		if session.Whistle != "" {
			srv.Debugw("Session is dangerous", "SessionId", req.SessionId)
			return nil, errors.New(session.Whistle)
		}
	}

	{ // Save message to db
		db_msg := &MpcMessage{
			SessionId:   req.SessionId,
			MemberIdSrc: req.MemberIdSrc,
			MemberIdDst: req.MemberIdDst,
			Purpose:     req.Purpose,
			Body:        req.Body,
		}
		err = db.Create(db_msg).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
	}

	return resp, nil
}

func (srv *SessionManager) GetMessage(
	ctx context.Context,
	req *pb.Message,
) (resp *pb.Message, err error) {
	db := srv.db
	resp = req

	var session *MpcSession
	{ // get session from db
		err = db.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		// If a whistle is blown, return with error.
		if session.Whistle != "" {
			srv.Debugw("Session is dangerous", "SessionId", req.SessionId)
			return nil, errors.New(session.Whistle)
		}
	}

	{ // get message from db
		var msg *MpcMessage
		err = db.
			Where("session_id = ? AND member_id_src = ? AND member_id_dst = ? AND purpose = ?",
				req.SessionId, req.MemberIdSrc, req.MemberIdDst, req.Purpose).
			Limit(1).Find(&msg).
			Error
		if err != nil {
			// Avoid spamming logs with "record not found" errors.
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				srv.Error(err)
				return nil, err
			}
		}
		if msg == nil {
			resp.Body = make([]byte, 0)
		} else {
			resp.Body = msg.Body
		}
	}

	return resp, nil
}
