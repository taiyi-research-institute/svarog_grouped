package bizlogic

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	proto "google.golang.org/protobuf/proto"
	pb "svarog_manager/proto/gen"
	util "svarog_manager/util"
)

func (srv *SessionManager) NewSession(
	ctx context.Context,
	req *pb.SessionConfig,
) (resp *pb.SessionConfig, err error) {
	tr := srv.db.Begin()
	resp = req

	{ // Validate the request
		assert_sestype := req.SessionType == "keygen" ||
			req.SessionType == "sign" ||
			req.SessionType == "reshare"
		if !assert_sestype {
			tr.Rollback()
			return nil, errors.New("Invalid session type")
		}

		if req.SessionType == "keygen" {
			_members := make(map[string]bool)
			_groups := make(map[string]bool)
			for _, group := range req.Groups {
				if group.IsReshare { // No group is reshare.
					tr.Rollback()
					return nil, errors.New("Any keygen group should not reshare")
				}
				if _groups[group.GroupName] { // Every group is unique.
					tr.Rollback()
					return nil, errors.New("Every keygen group should be unique")
				}
				_groups[group.GroupName] = true
				for _, member := range group.Members {
					if _members[member.MemberName] { // Every member is unique.
						tr.Rollback()
						return nil, errors.New("Every keygen member should be unique")
					}
					_members[member.MemberName] = true
					if !member.IsAttending { // Every member is attending.
						tr.Rollback()
						return nil, errors.New("Every keygen member should attend")
					}
				}
			}
			if len(_groups) < 1 { // At least one group.
				tr.Rollback()
				return nil, errors.New("At least one keygen group is required")
			}
			if len(_members) < 1 { // At least two members.
				tr.Rollback()
				return nil, errors.New("At lest one keygen members is required")
			}
		} else if req.SessionType == "sign" {
			_cdd := make(map[string]bool)
			_groups := make(map[string]bool)
			_gq := make(map[string]uint64)
			_gatt := make(map[string]uint64)
			_katt := uint64(0)
			_kq := req.KeyQuorum
			for _, group := range req.Groups {
				if group.IsReshare { // No group is reshare.
					tr.Rollback()
					return nil, errors.New("Any sign group should not reshare")
				}
				if _groups[group.GroupName] { // Every group is unique.
					tr.Rollback()
					return nil, errors.New("Every sign group should be unique")
				}
				_groups[group.GroupName] = true
				_gq[group.GroupName] = group.GroupQuorum
				for _, member := range group.Members {
					if _cdd[member.MemberName] { // Every member is unique.
						tr.Rollback()
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
				tr.Rollback()
				return nil, errors.New("At least one sign group is required")
			}
			if len(_cdd) < 1 { // At least two members.
				tr.Rollback()
				return nil, errors.New("At lest one sign candidate is required")
			}
			if _katt < _kq { // Key quorum is satisfied.
				tr.Rollback()
				return nil, errors.New("Key quorum is not satisfied")
			}
			for _, group := range req.Groups {
				if _gatt[group.GroupName] < _gq[group.GroupName] {
					tr.Rollback()
					return nil, errors.New("Group quorum is not satisfied")
				}
			}
		} else {
			{ // Analogous to sign
				_cdd := make(map[string]bool)
				_groups := make(map[string]bool)
				_gq := make(map[string]uint64)
				_gatt := make(map[string]uint64)
				_katt := uint64(0)
				_kq := req.KeyQuorum
				for _, group := range req.Groups {
					if group.IsReshare {
						continue;
					}
					if _groups[group.GroupName] { // Every group is unique.
						tr.Rollback()
						return nil, errors.New("Every non-reshare group should be unique")
					}
					_groups[group.GroupName] = true
					_gq[group.GroupName] = group.GroupQuorum
					for _, member := range group.Members {
						if _cdd[member.MemberName] { // Every member is unique.
							tr.Rollback()
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
					tr.Rollback()
					return nil, errors.New("At least one non-reshare group is required")
				}
				if len(_cdd) < 1 { // At least two members.
					tr.Rollback()
					return nil, errors.New("At lest one non-reshare candidate is required")
				}
				if _katt < _kq { // Key quorum is satisfied.
					tr.Rollback()
					return nil, errors.New("Non-reshare key quorum is not satisfied")
				}
				for _, group := range req.Groups {
					if _gatt[group.GroupName] < _gq[group.GroupName] {
						tr.Rollback()
						return nil, errors.New("Non-reshare group quorum is not satisfied")
					}
				}
			}

			{ // Analogous to keygen
				_members := make(map[string]bool)
				_groups := make(map[string]bool)
				for _, group := range req.Groups {
					if !group.IsReshare {
						continue
					}
					if _groups[group.GroupName] { // Every group is unique.
						tr.Rollback()
						return nil, errors.New("Every reshare group should be unique")
					}
					_groups[group.GroupName] = true
					for _, member := range group.Members {
						if _members[member.MemberName] { // Every member is unique.
							tr.Rollback()
							return nil, errors.New("Every reshare member should be unique")
						}
						_members[member.MemberName] = true
						if !member.IsAttending { // Every member is attending.
							tr.Rollback()
							return nil, errors.New("Every reshare member should attend")
						}
					}
				}
				if len(_groups) < 1 { // At least one group.
					tr.Rollback()
					return nil, errors.New("At least one reshare group is required")
				}
				if len(_members) < 1 { // At least one member.
					tr.Rollback()
					return nil, errors.New("At lest one reshare member is required")
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
		marshalled_tx_hashes, err := proto.Marshal(req.ToSign)
		new_session := MpcSession{
			SessionId:          req.SessionId,
			SessionType:        req.SessionType,
			KeyQuorum:          req.KeyQuorum,
			ReshareKeyQuorum:   req.ReshareKeyQuorum,
			ExpireBeforeFinish: req.ExpireBeforeFinish,
			ExpireAfterFinish:  req.ExpireAfterFinish,
			MarshalledTxHashes: marshalled_tx_hashes,
			Result:             make([]byte, 0),
			DataCache:          make([]byte, 0),
			TerminationHash:    make([]byte, 0),
			Whistle:            "",
		}

		err = tr.Create(&new_session).Error
		if err != nil {
			tr.Rollback()
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
			err = tr.Create(&new_group).Error
			if err != nil {
				tr.Rollback()
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
			err = tr.Create(&new_member).Error
			if err != nil {
				tr.Rollback()
				srv.Error(err)
				return nil, err
			}
		}
	}

	err = tr.Commit().Error
	if err != nil {
		tr.Rollback()
		srv.Error(err)
		return nil, err
	}
	return resp, nil
}

func (srv *SessionManager) TerminateSession(
	ctx context.Context,
	req *pb.SessionTermination,
) (resp *pb.Void, err error) {
	tr := srv.db.Begin()
	resp = &pb.Void{}

	var session *MpcSession
	{ // get session from db
		err = tr.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			tr.Rollback()
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		// If a whistle is blown, return with error.
		if session.Whistle != "" {
			tr.Rollback()
			srv.Debugw("Session is dangerous", "SessionId", req.SessionId)
			return nil, errors.New(session.Whistle)
		}
	}

	var member *MpcMember
	{ // get member from db
		err = tr.
			Where("session_id = ? AND member_id = ?", req.SessionId, req.MemberId).
			First(&member).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if member == nil {
			tr.Rollback()
			srv.Debugw("Member does not exist",
				"SessionId", req.SessionId, "MemberId", req.MemberId)
			return nil, errors.New("Member does not exist")
		}
		if !member.IsAttending {
			tr.Rollback()
			srv.Debugw("Member is not attending",
				"SessionId", req.SessionId, "MemberId", req.MemberId, "MemberName", member.MemberName)
			return nil, errors.New("Member is not attending")
		}
		if member.IsTerminated {
			tr.Rollback()
			srv.Debugw("Member is terminated",
				"SessionId", req.SessionId, "MemberId", req.MemberId, "MemberName", member.MemberName)
			return nil, nil
		}
	}

	marshalled := make([]byte, 0)
	{ // If the session doesn't have a Termination hash, update it;
		if len(session.TerminationHash) == 0 {
			marshalled, err = proto.Marshal(req.Fruit)
			if err != nil {
				tr.Rollback()
				srv.Error(err)
				return nil, err
			}
			session.TerminationHash = util.Blake2b(marshalled)
			err = tr.Save(session).Error
			if err != nil {
				tr.Rollback()
				srv.Error(err)
				return nil, err
			}
		} else { //// otherwise, check if it matches.
			marshalled, err = proto.Marshal(req.Fruit)
			if err != nil {
				tr.Rollback()
				srv.Error(err)
				return nil, err
			}
			hash2 := util.Blake2b(marshalled)
			if !bytes.Equal(session.TerminationHash, hash2) {
				tr.Rollback()
				srv.Debug("Termination hash mismatch")
				return nil, err
			}
		}
	}

	{ // Mark the member as terminated
		member.IsTerminated = true
		err = tr.Save(member).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
	}

	var ses_members []*MpcMember
	all_terminated := true
	{ // If the member is the last one submitting a result, save the result to session.
		err = tr.
			Where("session_id = ? AND member_id = ?",
				req.SessionId, req.MemberId).
			First(&ses_members).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		for _, ses_member := range ses_members {
			if ses_member.IsAttending && !ses_member.IsTerminated {
				all_terminated = false
				break
			}
		}
		if all_terminated {
			session.Result = marshalled
			err = tr.Save(session).Error
			if err != nil {
				tr.Rollback()
				srv.Error(err)
				return nil, err
			}
			// delete old messages to release memory or storage.
			err = tr.Delete(&MpcMessage{}, "session_id = ?", req.SessionId).Error
			if err != nil {
				tr.Rollback()
				srv.Error(err)
				return nil, err
			}
		}
	}

	err = tr.Commit().Error
	if err != nil {
		tr.Rollback()
		srv.Error(err)
		return nil, err
	}
	return resp, nil
}

func (srv *SessionManager) GetSessionConfig(
	ctx context.Context,
	req *pb.SessionId,
) (resp *pb.SessionConfig, err error) {
	tr := srv.db.Begin()
	resp = &pb.SessionConfig{}

	var session *MpcSession
	{ // get session from db
		err = tr.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			tr.Rollback()
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
	}

	var ses_groups []*MpcGroup
	{ // get groups from db
		err = tr.Where("session_id = ?", req.SessionId).
			Order("group_id ASC").
			Find(&ses_groups).
			Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if len(ses_groups) == 0 {
			tr.Rollback()
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
		err = tr.Where("session_id = ? AND group_id = ?", req.SessionId, resp_group.GroupId).
			Order("member_id ASC").
			Find(&ses_members).
			Error
		if err != nil {
			tr.Rollback()
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
		err = proto.Unmarshal(session.Result, resp.ToSign)
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
	}

	err = tr.Commit().Error
	if err != nil {
		tr.Rollback()
		srv.Error(err)
		return nil, err
	}
	return resp, nil
}

func (srv *SessionManager) GetSessionFruit(
	ctx context.Context,
	req *pb.SessionId,
) (resp *pb.SessionFruit, err error) {
	tr := srv.db.Begin()
	resp = &pb.SessionFruit{}

	// If a whistle is blown, return with error.
	var session *MpcSession
	{ // get session from db
		err = tr.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			tr.Rollback()
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		// If a whistle is blown, return with error.
		if session.Whistle != "" {
			tr.Rollback()
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
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
	}

	err = tr.Commit().Error
	if err != nil {
		tr.Rollback()
		srv.Error(err)
		return nil, err
	}
	return resp, nil
}

func (srv *SessionManager) BlowWhistle(
	ctx context.Context,
	req *pb.Whistle,
) (resp *pb.Void, err error) {
	tr := srv.db.Begin()

	var session *MpcSession
	{ // Append req.Message to session.Whistle
		err = tr.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			tr.Rollback()
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		session.Whistle += req.Message
		err = tr.Save(session).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
	}

	err = tr.Commit().Error
	if err != nil {
		tr.Rollback()
		srv.Error(err)
		return nil, err
	}
	return resp, nil
}

func (srv *SessionManager) PostMessage(
	ctx context.Context,
	req *pb.Message,
) (resp *pb.Void, err error) {
	tr := srv.db.Begin()
	resp = &pb.Void{}

	// If a whistle is blown, return with error.
	var session *MpcSession
	{ // get session from db
		err = tr.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			tr.Rollback()
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		// If a whistle is blown, return with error.
		if session.Whistle != "" {
			tr.Rollback()
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
		err = tr.Create(db_msg).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
	}

	err = tr.Commit().Error
	if err != nil {
		tr.Rollback()
		srv.Error(err)
		return nil, err
	}
	return resp, nil
}

func (srv *SessionManager) GetMessage(
	ctx context.Context,
	req *pb.Message,
) (resp *pb.Message, err error) {
	tr := srv.db.Begin()
	resp = req

	var session *MpcSession
	{ // get session from db
		err = tr.Where("session_id = ?", req.SessionId).First(&session).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if session == nil {
			tr.Rollback()
			srv.Debugw("Session does not exist", "SessionId", req.SessionId)
			return nil, errors.New("Session does not exist")
		}
		// If a whistle is blown, return with error.
		if session.Whistle != "" {
			tr.Rollback()
			srv.Debugw("Session is dangerous", "SessionId", req.SessionId)
			return nil, errors.New(session.Whistle)
		}
	}

	{ // get message from db
		var msg *MpcMessage
		err = tr.
			Where("session_id = ? AND member_id_src = ? AND member_id_dst = ? AND purpose = ?",
				req.SessionId, req.MemberIdSrc, req.MemberIdDst, req.Purpose).
			First(&msg).
			Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return nil, err
		}
		if msg == nil {
			tr.Rollback()
			srv.Debugw("Message does not exist",
				"SessionId", req.SessionId,
				"MemberIdSrc", req.MemberIdSrc,
				"MemberIdDst", req.MemberIdDst,
				"Purpose", req.Purpose)
			return nil, errors.New("Message does not exist")
		}
		resp.Body = msg.Body
	}

	err = tr.Commit().Error
	if err != nil {
		tr.Rollback()
		srv.Error(err)
		return nil, err
	}
	return resp, nil
}
