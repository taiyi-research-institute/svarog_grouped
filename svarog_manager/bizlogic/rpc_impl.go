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
		// TODO: Assert that session type is one of "keygen", "sign", "reshare".
		// TODO: If the session type is "keygen", assert that
		//// 1) No group "is_reshare";
		//// 2) every member "is_attending".
		// TODO: If the session type is "sign", assert that
		//// 1) No group "is_reshare";
		//// 2) numbers of "is_attending" pass the quorum checks.
		// TODO: If the session type is "reshare", assert that
		//// 1) At least one group "is_reshare", and one group not "is_reshare";
		//// 2) In groups that not "is_reshare", numbers of "is_attending" pass the quorum checks;
		//// 3) In groups that "is_reshare", every member "is_attending".
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
