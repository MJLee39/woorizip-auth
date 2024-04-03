package main

import (
	"context"
	"log"
	"net"
	"os"
	"time"

	"github.com/TeamWAF/woorizip-account/pb/accountpb"
	"github.com/TeamWAF/woorizip-auth/pb/authpb"
	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	defaultSigningKey          = "7f9347b402a118a7a10cebee68b999a9546dc62cae864d47a6be0f133390f49c20b6fb5d2d6d35bc5faf5b66cc2b0d38cb1019ecee5b6d236e3ec309212a1a62"
	defaultTokenExpiration     = time.Hour * 24
	defaultRefreshTokenExpirat = time.Hour * 24 * 7
)

func main() {
	signingKey := getEnv("SIGNING_KEY", defaultSigningKey)
	serverAddr := getEnv("SERVER_ADDR", ":1337")
	listenAddr := getEnv("LISTEN_ADDR", ":50052")

	conn, accountClient := setupAccountServiceClient(serverAddr)
	defer conn.Close()

	authServer := newAuthServer(accountClient, signingKey)
	startGRPCServer(listenAddr, authServer)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func setupAccountServiceClient(serverAddr string) (*grpc.ClientConn, accountpb.AccountServiceClient) {
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to account service at %s: %v", serverAddr, err)
	}
	return conn, accountpb.NewAccountServiceClient(conn)
}

func newAuthServer(accountClient accountpb.AccountServiceClient, signingKey string) *AuthServer {
	return &AuthServer{
		accountClient: accountClient,
		signingKey:    signingKey,
	}
}

func startGRPCServer(listenAddr string, authServer *AuthServer) {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	s := grpc.NewServer()
	authpb.RegisterAuthServiceServer(s, authServer)
	reflection.Register(s)
	log.Printf("Starting gRPC server on %s", listenAddr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC server over %s: %v", listenAddr, err)
	}
}

type AuthServer struct {
	authpb.UnimplementedAuthServiceServer
	accountClient accountpb.AccountServiceClient
	signingKey    string
}

func (s *AuthServer) Auth(ctx context.Context, req *authpb.AuthReq) (*authpb.AuthResp, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request is nil")
	}

	accountResp, err := s.accountClient.GetAccountByProvider(ctx, &accountpb.GetAccountByProviderReq{
		Provider:       req.Provider,
		ProviderUserId: req.ProviderUserId,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Cannot find account: %v", err)
	}

	token, err := s.generateJWTToken(accountResp.Account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate JWT token: %v", err)
	}

	return &authpb.AuthResp{Token: token}, nil
}

func (s *AuthServer) generateJWTToken(account *accountpb.Account) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = account.Id
	claims["role"] = account.Role
	claims["exp"] = time.Now().Add(defaultTokenExpiration).Unix()

	tokenString, err := token.SignedString([]byte(s.signingKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
