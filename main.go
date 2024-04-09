package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/TeamWAF/woorizip-account/pb/accountpb"
	"github.com/TeamWAF/woorizip-auth/pb/authpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	defaultTokenExpiration        = time.Hour * 24
	defaultRefreshTokenExpiration = time.Hour * 24 * 7
)

var (
	signingKeyByte = []byte{149, 196, 179, 66, 205, 186, 90, 225, 216, 112, 143, 60, 97, 113, 182, 158, 139, 44, 130, 137, 36, 151, 204, 65, 216, 228, 214, 191, 70, 162, 99, 63, 204, 198, 43, 46, 162, 135, 84, 115, 198, 104, 142, 135, 66, 165, 103, 110, 201, 103, 254, 92, 240, 147, 160, 27, 200, 251, 7, 163, 224, 108, 77, 71}
)

func main() {

	serverAddr := getEnv("SERVER_ADDR", ":1337")
	listenAddr := getEnv("LISTEN_ADDR", ":50052")

	secretKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(signingKeyByte)
	if err != nil {
		log.Fatalf("Failed to create secret key: %v", err)
	}

	log.Println("secretKey: ", secretKey)

	conn, accountClient := setupAccountServiceClient(serverAddr)
	defer conn.Close()

	authServer := newAuthServer(accountClient, secretKey)
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

func newAuthServer(accountClient accountpb.AccountServiceClient, secretKey paseto.V4AsymmetricSecretKey) *AuthServer {
	return &AuthServer{
		accountClient: accountClient,
		secretKey:     secretKey,
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
	secretKey     paseto.V4AsymmetricSecretKey
}

// Auth provider 유형과 provider 유저 아이디로 account 정보를 찾아서 JWT 토큰을 발급한다.
func (s *AuthServer) Auth(ctx context.Context, req *authpb.AuthReq) (*authpb.AuthResp, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request is nil")
	}

	accountResp, err := s.accountClient.GetAccountByProvider(ctx, &accountpb.GetAccountByProviderReq{
		Provider:       req.Provider,
		ProviderUserId: req.ProviderUserId,
	})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "계정이 존재하지 않음")
	}

	access_token, err := s.generateAccessToken(accountResp.Account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate access token: %v", err)
	}

	refresh_token, err := s.generateRefreshToken(accountResp.Account.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate refresh token: %v", err)
	}

	return &authpb.AuthResp{AccessToken: access_token, RefreshToken: refresh_token, Error: ""}, nil
}

func (s *AuthServer) AuthCheck(ctx context.Context, req *authpb.AuthCheckReq) (*authpb.AuthCheckResp, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request is nil")
	}

	tokenString := req.Token
	parser := paseto.NewParser()

	// SecretKey로부터 PublicKey 생성
	publicKey := s.secretKey.Public()

	// Paseto 토큰 파싱 및 검증
	token, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		log.Println("Failed to parse token: ", err)
		return nil, err
	}

	// 토큰 규칙 검증
	rules := []paseto.Rule{
		paseto.ForAudience("audience"),
		paseto.IssuedBy("issuer"),
		paseto.Subject("subject"),
		paseto.NotBeforeNbf(),
		paseto.NotExpired(),
		paseto.IdentifiedBy("identifier"),
	}

	for _, rule := range rules {
		if err := rule(*token); err != nil {
			// 검증 실패 처리
			fmt.Println("Token validation failed:", err)
			return &authpb.AuthCheckResp{
				Valid: false,
				Error: err.Error(),
			}, nil
		}
	}

	return &authpb.AuthCheckResp{
		Valid: true,
		Error: "",
	}, nil
}

func (s *AuthServer) generateAccessToken(account *accountpb.Account) (string, error) {
	token := paseto.NewToken()

	token.SetAudience("audience")
	token.SetJti("identifier")
	token.SetIssuer("issuer")
	token.SetSubject("subject")

	token.SetExpiration(time.Now().Add(defaultTokenExpiration))
	token.SetNotBefore(time.Now())
	token.SetIssuedAt(time.Now())

	token.SetString("id", account.Id)
	token.SetString("role", account.Role)

	signed := token.V4Sign(s.secretKey, nil)
	return signed, nil
}

func (s *AuthServer) generateRefreshToken(accountId string) (string, error) {
	token := paseto.NewToken()

	token.SetAudience("audience")
	token.SetJti("identifier")
	token.SetIssuer("issuer")
	token.SetSubject("subject")

	token.SetExpiration(time.Now().Add(defaultRefreshTokenExpiration))
	token.SetNotBefore(time.Now())
	token.SetIssuedAt(time.Now())

	token.SetString("id", accountId)

	signed := token.V4Sign(s.secretKey, nil)
	return signed, nil
}
