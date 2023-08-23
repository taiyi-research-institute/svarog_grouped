// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.20.3
// source: svarog.proto

package gen

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	MpcPeer_JoinSession_FullMethodName      = "/svarog.MpcPeer/JoinSession"
	MpcPeer_GetSessionConfig_FullMethodName = "/svarog.MpcPeer/GetSessionConfig"
	MpcPeer_AbortSession_FullMethodName     = "/svarog.MpcPeer/AbortSession"
)

// MpcPeerClient is the client API for MpcPeer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MpcPeerClient interface {
	JoinSession(ctx context.Context, in *JoinSessionRequest, opts ...grpc.CallOption) (*SessionResult, error)
	GetSessionConfig(ctx context.Context, in *GetSessionConfigRequest, opts ...grpc.CallOption) (*SessionConfig, error)
	AbortSession(ctx context.Context, in *AbortSessionRequest, opts ...grpc.CallOption) (*Void, error)
}

type mpcPeerClient struct {
	cc grpc.ClientConnInterface
}

func NewMpcPeerClient(cc grpc.ClientConnInterface) MpcPeerClient {
	return &mpcPeerClient{cc}
}

func (c *mpcPeerClient) JoinSession(ctx context.Context, in *JoinSessionRequest, opts ...grpc.CallOption) (*SessionResult, error) {
	out := new(SessionResult)
	err := c.cc.Invoke(ctx, MpcPeer_JoinSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mpcPeerClient) GetSessionConfig(ctx context.Context, in *GetSessionConfigRequest, opts ...grpc.CallOption) (*SessionConfig, error) {
	out := new(SessionConfig)
	err := c.cc.Invoke(ctx, MpcPeer_GetSessionConfig_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mpcPeerClient) AbortSession(ctx context.Context, in *AbortSessionRequest, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MpcPeer_AbortSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MpcPeerServer is the server API for MpcPeer service.
// All implementations must embed UnimplementedMpcPeerServer
// for forward compatibility
type MpcPeerServer interface {
	JoinSession(context.Context, *JoinSessionRequest) (*SessionResult, error)
	GetSessionConfig(context.Context, *GetSessionConfigRequest) (*SessionConfig, error)
	AbortSession(context.Context, *AbortSessionRequest) (*Void, error)
	mustEmbedUnimplementedMpcPeerServer()
}

// UnimplementedMpcPeerServer must be embedded to have forward compatible implementations.
type UnimplementedMpcPeerServer struct {
}

func (UnimplementedMpcPeerServer) JoinSession(context.Context, *JoinSessionRequest) (*SessionResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method JoinSession not implemented")
}
func (UnimplementedMpcPeerServer) GetSessionConfig(context.Context, *GetSessionConfigRequest) (*SessionConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSessionConfig not implemented")
}
func (UnimplementedMpcPeerServer) AbortSession(context.Context, *AbortSessionRequest) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AbortSession not implemented")
}
func (UnimplementedMpcPeerServer) mustEmbedUnimplementedMpcPeerServer() {}

// UnsafeMpcPeerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MpcPeerServer will
// result in compilation errors.
type UnsafeMpcPeerServer interface {
	mustEmbedUnimplementedMpcPeerServer()
}

func RegisterMpcPeerServer(s grpc.ServiceRegistrar, srv MpcPeerServer) {
	s.RegisterService(&MpcPeer_ServiceDesc, srv)
}

func _MpcPeer_JoinSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(JoinSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcPeerServer).JoinSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcPeer_JoinSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcPeerServer).JoinSession(ctx, req.(*JoinSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MpcPeer_GetSessionConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSessionConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcPeerServer).GetSessionConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcPeer_GetSessionConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcPeerServer).GetSessionConfig(ctx, req.(*GetSessionConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MpcPeer_AbortSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AbortSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcPeerServer).AbortSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcPeer_AbortSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcPeerServer).AbortSession(ctx, req.(*AbortSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MpcPeer_ServiceDesc is the grpc.ServiceDesc for MpcPeer service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MpcPeer_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "svarog.MpcPeer",
	HandlerType: (*MpcPeerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "JoinSession",
			Handler:    _MpcPeer_JoinSession_Handler,
		},
		{
			MethodName: "GetSessionConfig",
			Handler:    _MpcPeer_GetSessionConfig_Handler,
		},
		{
			MethodName: "AbortSession",
			Handler:    _MpcPeer_AbortSession_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "svarog.proto",
}

const (
	MpcSessionManager_NewSession_FullMethodName       = "/svarog.MpcSessionManager/NewSession"
	MpcSessionManager_GetSessionConfig_FullMethodName = "/svarog.MpcSessionManager/GetSessionConfig"
	MpcSessionManager_BlowWhistle_FullMethodName      = "/svarog.MpcSessionManager/BlowWhistle"
	MpcSessionManager_PostMessage_FullMethodName      = "/svarog.MpcSessionManager/PostMessage"
	MpcSessionManager_GetMessage_FullMethodName       = "/svarog.MpcSessionManager/GetMessage"
	MpcSessionManager_TerminateSession_FullMethodName = "/svarog.MpcSessionManager/TerminateSession"
)

// MpcSessionManagerClient is the client API for MpcSessionManager service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MpcSessionManagerClient interface {
	NewSession(ctx context.Context, in *SessionConfig, opts ...grpc.CallOption) (*Void, error)
	GetSessionConfig(ctx context.Context, in *SessionId, opts ...grpc.CallOption) (*SessionConfig, error)
	BlowWhistle(ctx context.Context, in *Whistle, opts ...grpc.CallOption) (*Void, error)
	PostMessage(ctx context.Context, in *Message, opts ...grpc.CallOption) (*Void, error)
	GetMessage(ctx context.Context, in *Message, opts ...grpc.CallOption) (*Message, error)
	TerminateSession(ctx context.Context, in *SessionTermination, opts ...grpc.CallOption) (*Void, error)
}

type mpcSessionManagerClient struct {
	cc grpc.ClientConnInterface
}

func NewMpcSessionManagerClient(cc grpc.ClientConnInterface) MpcSessionManagerClient {
	return &mpcSessionManagerClient{cc}
}

func (c *mpcSessionManagerClient) NewSession(ctx context.Context, in *SessionConfig, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MpcSessionManager_NewSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mpcSessionManagerClient) GetSessionConfig(ctx context.Context, in *SessionId, opts ...grpc.CallOption) (*SessionConfig, error) {
	out := new(SessionConfig)
	err := c.cc.Invoke(ctx, MpcSessionManager_GetSessionConfig_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mpcSessionManagerClient) BlowWhistle(ctx context.Context, in *Whistle, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MpcSessionManager_BlowWhistle_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mpcSessionManagerClient) PostMessage(ctx context.Context, in *Message, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MpcSessionManager_PostMessage_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mpcSessionManagerClient) GetMessage(ctx context.Context, in *Message, opts ...grpc.CallOption) (*Message, error) {
	out := new(Message)
	err := c.cc.Invoke(ctx, MpcSessionManager_GetMessage_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mpcSessionManagerClient) TerminateSession(ctx context.Context, in *SessionTermination, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, MpcSessionManager_TerminateSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MpcSessionManagerServer is the server API for MpcSessionManager service.
// All implementations must embed UnimplementedMpcSessionManagerServer
// for forward compatibility
type MpcSessionManagerServer interface {
	NewSession(context.Context, *SessionConfig) (*Void, error)
	GetSessionConfig(context.Context, *SessionId) (*SessionConfig, error)
	BlowWhistle(context.Context, *Whistle) (*Void, error)
	PostMessage(context.Context, *Message) (*Void, error)
	GetMessage(context.Context, *Message) (*Message, error)
	TerminateSession(context.Context, *SessionTermination) (*Void, error)
	mustEmbedUnimplementedMpcSessionManagerServer()
}

// UnimplementedMpcSessionManagerServer must be embedded to have forward compatible implementations.
type UnimplementedMpcSessionManagerServer struct {
}

func (UnimplementedMpcSessionManagerServer) NewSession(context.Context, *SessionConfig) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method NewSession not implemented")
}
func (UnimplementedMpcSessionManagerServer) GetSessionConfig(context.Context, *SessionId) (*SessionConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSessionConfig not implemented")
}
func (UnimplementedMpcSessionManagerServer) BlowWhistle(context.Context, *Whistle) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BlowWhistle not implemented")
}
func (UnimplementedMpcSessionManagerServer) PostMessage(context.Context, *Message) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostMessage not implemented")
}
func (UnimplementedMpcSessionManagerServer) GetMessage(context.Context, *Message) (*Message, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMessage not implemented")
}
func (UnimplementedMpcSessionManagerServer) TerminateSession(context.Context, *SessionTermination) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TerminateSession not implemented")
}
func (UnimplementedMpcSessionManagerServer) mustEmbedUnimplementedMpcSessionManagerServer() {}

// UnsafeMpcSessionManagerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MpcSessionManagerServer will
// result in compilation errors.
type UnsafeMpcSessionManagerServer interface {
	mustEmbedUnimplementedMpcSessionManagerServer()
}

func RegisterMpcSessionManagerServer(s grpc.ServiceRegistrar, srv MpcSessionManagerServer) {
	s.RegisterService(&MpcSessionManager_ServiceDesc, srv)
}

func _MpcSessionManager_NewSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SessionConfig)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcSessionManagerServer).NewSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcSessionManager_NewSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcSessionManagerServer).NewSession(ctx, req.(*SessionConfig))
	}
	return interceptor(ctx, in, info, handler)
}

func _MpcSessionManager_GetSessionConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SessionId)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcSessionManagerServer).GetSessionConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcSessionManager_GetSessionConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcSessionManagerServer).GetSessionConfig(ctx, req.(*SessionId))
	}
	return interceptor(ctx, in, info, handler)
}

func _MpcSessionManager_BlowWhistle_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Whistle)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcSessionManagerServer).BlowWhistle(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcSessionManager_BlowWhistle_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcSessionManagerServer).BlowWhistle(ctx, req.(*Whistle))
	}
	return interceptor(ctx, in, info, handler)
}

func _MpcSessionManager_PostMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Message)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcSessionManagerServer).PostMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcSessionManager_PostMessage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcSessionManagerServer).PostMessage(ctx, req.(*Message))
	}
	return interceptor(ctx, in, info, handler)
}

func _MpcSessionManager_GetMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Message)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcSessionManagerServer).GetMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcSessionManager_GetMessage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcSessionManagerServer).GetMessage(ctx, req.(*Message))
	}
	return interceptor(ctx, in, info, handler)
}

func _MpcSessionManager_TerminateSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SessionTermination)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MpcSessionManagerServer).TerminateSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MpcSessionManager_TerminateSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MpcSessionManagerServer).TerminateSession(ctx, req.(*SessionTermination))
	}
	return interceptor(ctx, in, info, handler)
}

// MpcSessionManager_ServiceDesc is the grpc.ServiceDesc for MpcSessionManager service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MpcSessionManager_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "svarog.MpcSessionManager",
	HandlerType: (*MpcSessionManagerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "NewSession",
			Handler:    _MpcSessionManager_NewSession_Handler,
		},
		{
			MethodName: "GetSessionConfig",
			Handler:    _MpcSessionManager_GetSessionConfig_Handler,
		},
		{
			MethodName: "BlowWhistle",
			Handler:    _MpcSessionManager_BlowWhistle_Handler,
		},
		{
			MethodName: "PostMessage",
			Handler:    _MpcSessionManager_PostMessage_Handler,
		},
		{
			MethodName: "GetMessage",
			Handler:    _MpcSessionManager_GetMessage_Handler,
		},
		{
			MethodName: "TerminateSession",
			Handler:    _MpcSessionManager_TerminateSession_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "svarog.proto",
}
