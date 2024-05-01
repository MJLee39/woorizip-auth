// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: proto/auth.proto

package protoconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	proto "github.com/teamwaf/woorizip-auth/proto"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// AuthServiceName is the fully-qualified name of the AuthService service.
	AuthServiceName = "auth.AuthService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// AuthServiceAuthProcedure is the fully-qualified name of the AuthService's Auth RPC.
	AuthServiceAuthProcedure = "/auth.AuthService/Auth"
	// AuthServiceAuthCheckProcedure is the fully-qualified name of the AuthService's AuthCheck RPC.
	AuthServiceAuthCheckProcedure = "/auth.AuthService/AuthCheck"
	// AuthServiceAuthRefreshProcedure is the fully-qualified name of the AuthService's AuthRefresh RPC.
	AuthServiceAuthRefreshProcedure = "/auth.AuthService/AuthRefresh"
	// AuthServiceAuthLogoutProcedure is the fully-qualified name of the AuthService's AuthLogout RPC.
	AuthServiceAuthLogoutProcedure = "/auth.AuthService/AuthLogout"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	authServiceServiceDescriptor           = proto.File_proto_auth_proto.Services().ByName("AuthService")
	authServiceAuthMethodDescriptor        = authServiceServiceDescriptor.Methods().ByName("Auth")
	authServiceAuthCheckMethodDescriptor   = authServiceServiceDescriptor.Methods().ByName("AuthCheck")
	authServiceAuthRefreshMethodDescriptor = authServiceServiceDescriptor.Methods().ByName("AuthRefresh")
	authServiceAuthLogoutMethodDescriptor  = authServiceServiceDescriptor.Methods().ByName("AuthLogout")
)

// AuthServiceClient is a client for the auth.AuthService service.
type AuthServiceClient interface {
	Auth(context.Context, *connect.Request[proto.AuthReq]) (*connect.Response[proto.AuthResp], error)
	AuthCheck(context.Context, *connect.Request[proto.AuthCheckReq]) (*connect.Response[proto.AuthCheckResp], error)
	AuthRefresh(context.Context, *connect.Request[proto.AuthRefreshReq]) (*connect.Response[proto.AuthRefreshResp], error)
	AuthLogout(context.Context, *connect.Request[proto.AuthLogoutReq]) (*connect.Response[proto.AuthLogoutResp], error)
}

// NewAuthServiceClient constructs a client for the auth.AuthService service. By default, it uses
// the Connect protocol with the binary Protobuf Codec, asks for gzipped responses, and sends
// uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or
// connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewAuthServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) AuthServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &authServiceClient{
		auth: connect.NewClient[proto.AuthReq, proto.AuthResp](
			httpClient,
			baseURL+AuthServiceAuthProcedure,
			connect.WithSchema(authServiceAuthMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		authCheck: connect.NewClient[proto.AuthCheckReq, proto.AuthCheckResp](
			httpClient,
			baseURL+AuthServiceAuthCheckProcedure,
			connect.WithSchema(authServiceAuthCheckMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		authRefresh: connect.NewClient[proto.AuthRefreshReq, proto.AuthRefreshResp](
			httpClient,
			baseURL+AuthServiceAuthRefreshProcedure,
			connect.WithSchema(authServiceAuthRefreshMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		authLogout: connect.NewClient[proto.AuthLogoutReq, proto.AuthLogoutResp](
			httpClient,
			baseURL+AuthServiceAuthLogoutProcedure,
			connect.WithSchema(authServiceAuthLogoutMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// authServiceClient implements AuthServiceClient.
type authServiceClient struct {
	auth        *connect.Client[proto.AuthReq, proto.AuthResp]
	authCheck   *connect.Client[proto.AuthCheckReq, proto.AuthCheckResp]
	authRefresh *connect.Client[proto.AuthRefreshReq, proto.AuthRefreshResp]
	authLogout  *connect.Client[proto.AuthLogoutReq, proto.AuthLogoutResp]
}

// Auth calls auth.AuthService.Auth.
func (c *authServiceClient) Auth(ctx context.Context, req *connect.Request[proto.AuthReq]) (*connect.Response[proto.AuthResp], error) {
	return c.auth.CallUnary(ctx, req)
}

// AuthCheck calls auth.AuthService.AuthCheck.
func (c *authServiceClient) AuthCheck(ctx context.Context, req *connect.Request[proto.AuthCheckReq]) (*connect.Response[proto.AuthCheckResp], error) {
	return c.authCheck.CallUnary(ctx, req)
}

// AuthRefresh calls auth.AuthService.AuthRefresh.
func (c *authServiceClient) AuthRefresh(ctx context.Context, req *connect.Request[proto.AuthRefreshReq]) (*connect.Response[proto.AuthRefreshResp], error) {
	return c.authRefresh.CallUnary(ctx, req)
}

// AuthLogout calls auth.AuthService.AuthLogout.
func (c *authServiceClient) AuthLogout(ctx context.Context, req *connect.Request[proto.AuthLogoutReq]) (*connect.Response[proto.AuthLogoutResp], error) {
	return c.authLogout.CallUnary(ctx, req)
}

// AuthServiceHandler is an implementation of the auth.AuthService service.
type AuthServiceHandler interface {
	Auth(context.Context, *connect.Request[proto.AuthReq]) (*connect.Response[proto.AuthResp], error)
	AuthCheck(context.Context, *connect.Request[proto.AuthCheckReq]) (*connect.Response[proto.AuthCheckResp], error)
	AuthRefresh(context.Context, *connect.Request[proto.AuthRefreshReq]) (*connect.Response[proto.AuthRefreshResp], error)
	AuthLogout(context.Context, *connect.Request[proto.AuthLogoutReq]) (*connect.Response[proto.AuthLogoutResp], error)
}

// NewAuthServiceHandler builds an HTTP handler from the service implementation. It returns the path
// on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewAuthServiceHandler(svc AuthServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	authServiceAuthHandler := connect.NewUnaryHandler(
		AuthServiceAuthProcedure,
		svc.Auth,
		connect.WithSchema(authServiceAuthMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceAuthCheckHandler := connect.NewUnaryHandler(
		AuthServiceAuthCheckProcedure,
		svc.AuthCheck,
		connect.WithSchema(authServiceAuthCheckMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceAuthRefreshHandler := connect.NewUnaryHandler(
		AuthServiceAuthRefreshProcedure,
		svc.AuthRefresh,
		connect.WithSchema(authServiceAuthRefreshMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	authServiceAuthLogoutHandler := connect.NewUnaryHandler(
		AuthServiceAuthLogoutProcedure,
		svc.AuthLogout,
		connect.WithSchema(authServiceAuthLogoutMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/auth.AuthService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case AuthServiceAuthProcedure:
			authServiceAuthHandler.ServeHTTP(w, r)
		case AuthServiceAuthCheckProcedure:
			authServiceAuthCheckHandler.ServeHTTP(w, r)
		case AuthServiceAuthRefreshProcedure:
			authServiceAuthRefreshHandler.ServeHTTP(w, r)
		case AuthServiceAuthLogoutProcedure:
			authServiceAuthLogoutHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedAuthServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedAuthServiceHandler struct{}

func (UnimplementedAuthServiceHandler) Auth(context.Context, *connect.Request[proto.AuthReq]) (*connect.Response[proto.AuthResp], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.AuthService.Auth is not implemented"))
}

func (UnimplementedAuthServiceHandler) AuthCheck(context.Context, *connect.Request[proto.AuthCheckReq]) (*connect.Response[proto.AuthCheckResp], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.AuthService.AuthCheck is not implemented"))
}

func (UnimplementedAuthServiceHandler) AuthRefresh(context.Context, *connect.Request[proto.AuthRefreshReq]) (*connect.Response[proto.AuthRefreshResp], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.AuthService.AuthRefresh is not implemented"))
}

func (UnimplementedAuthServiceHandler) AuthLogout(context.Context, *connect.Request[proto.AuthLogoutReq]) (*connect.Response[proto.AuthLogoutResp], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("auth.AuthService.AuthLogout is not implemented"))
}
