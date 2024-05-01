// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: proto/auth.proto

package proto

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
	AuthService_Auth_FullMethodName        = "/auth.AuthService/Auth"
	AuthService_AuthCheck_FullMethodName   = "/auth.AuthService/AuthCheck"
	AuthService_AuthRefresh_FullMethodName = "/auth.AuthService/AuthRefresh"
	AuthService_AuthLogout_FullMethodName  = "/auth.AuthService/AuthLogout"
)

// AuthServiceClient is the client API for AuthService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AuthServiceClient interface {
	Auth(ctx context.Context, in *AuthReq, opts ...grpc.CallOption) (*AuthResp, error)
	AuthCheck(ctx context.Context, in *AuthCheckReq, opts ...grpc.CallOption) (*AuthCheckResp, error)
	AuthRefresh(ctx context.Context, in *AuthRefreshReq, opts ...grpc.CallOption) (*AuthRefreshResp, error)
	AuthLogout(ctx context.Context, in *AuthLogoutReq, opts ...grpc.CallOption) (*AuthLogoutResp, error)
}

type authServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthServiceClient(cc grpc.ClientConnInterface) AuthServiceClient {
	return &authServiceClient{cc}
}

func (c *authServiceClient) Auth(ctx context.Context, in *AuthReq, opts ...grpc.CallOption) (*AuthResp, error) {
	out := new(AuthResp)
	err := c.cc.Invoke(ctx, AuthService_Auth_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) AuthCheck(ctx context.Context, in *AuthCheckReq, opts ...grpc.CallOption) (*AuthCheckResp, error) {
	out := new(AuthCheckResp)
	err := c.cc.Invoke(ctx, AuthService_AuthCheck_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) AuthRefresh(ctx context.Context, in *AuthRefreshReq, opts ...grpc.CallOption) (*AuthRefreshResp, error) {
	out := new(AuthRefreshResp)
	err := c.cc.Invoke(ctx, AuthService_AuthRefresh_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) AuthLogout(ctx context.Context, in *AuthLogoutReq, opts ...grpc.CallOption) (*AuthLogoutResp, error) {
	out := new(AuthLogoutResp)
	err := c.cc.Invoke(ctx, AuthService_AuthLogout_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServiceServer is the server API for AuthService service.
// All implementations must embed UnimplementedAuthServiceServer
// for forward compatibility
type AuthServiceServer interface {
	Auth(context.Context, *AuthReq) (*AuthResp, error)
	AuthCheck(context.Context, *AuthCheckReq) (*AuthCheckResp, error)
	AuthRefresh(context.Context, *AuthRefreshReq) (*AuthRefreshResp, error)
	AuthLogout(context.Context, *AuthLogoutReq) (*AuthLogoutResp, error)
	mustEmbedUnimplementedAuthServiceServer()
}

// UnimplementedAuthServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAuthServiceServer struct {
}

func (UnimplementedAuthServiceServer) Auth(context.Context, *AuthReq) (*AuthResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Auth not implemented")
}
func (UnimplementedAuthServiceServer) AuthCheck(context.Context, *AuthCheckReq) (*AuthCheckResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthCheck not implemented")
}
func (UnimplementedAuthServiceServer) AuthRefresh(context.Context, *AuthRefreshReq) (*AuthRefreshResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthRefresh not implemented")
}
func (UnimplementedAuthServiceServer) AuthLogout(context.Context, *AuthLogoutReq) (*AuthLogoutResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthLogout not implemented")
}
func (UnimplementedAuthServiceServer) mustEmbedUnimplementedAuthServiceServer() {}

// UnsafeAuthServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AuthServiceServer will
// result in compilation errors.
type UnsafeAuthServiceServer interface {
	mustEmbedUnimplementedAuthServiceServer()
}

func RegisterAuthServiceServer(s grpc.ServiceRegistrar, srv AuthServiceServer) {
	s.RegisterService(&AuthService_ServiceDesc, srv)
}

func _AuthService_Auth_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).Auth(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_Auth_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).Auth(ctx, req.(*AuthReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_AuthCheck_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthCheckReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).AuthCheck(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_AuthCheck_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).AuthCheck(ctx, req.(*AuthCheckReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_AuthRefresh_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthRefreshReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).AuthRefresh(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_AuthRefresh_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).AuthRefresh(ctx, req.(*AuthRefreshReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_AuthLogout_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthLogoutReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).AuthLogout(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AuthService_AuthLogout_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).AuthLogout(ctx, req.(*AuthLogoutReq))
	}
	return interceptor(ctx, in, info, handler)
}

// AuthService_ServiceDesc is the grpc.ServiceDesc for AuthService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AuthService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "auth.AuthService",
	HandlerType: (*AuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Auth",
			Handler:    _AuthService_Auth_Handler,
		},
		{
			MethodName: "AuthCheck",
			Handler:    _AuthService_AuthCheck_Handler,
		},
		{
			MethodName: "AuthRefresh",
			Handler:    _AuthService_AuthRefresh_Handler,
		},
		{
			MethodName: "AuthLogout",
			Handler:    _AuthService_AuthLogout_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/auth.proto",
}