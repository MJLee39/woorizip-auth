package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/TeamWAF/woorizip-auth/utils"

	"github.com/TeamWAF/woorizip-gateway/gen/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	defaultTokenExpiration        = time.Hour * 24
	defaultRefreshTokenExpiration = time.Hour * 24 * 7
	listenPort                    = ":80"
	accountServer                 = "service-account:80"
)

var (
	signingKeyByte = []byte{149, 196, 179, 66, 205, 186, 90, 225, 216, 112, 143, 60, 97, 113, 182, 158, 139, 44, 130, 137, 36, 151, 204, 65, 216, 228, 214, 191, 70, 162, 99, 63, 204, 198, 43, 46, 162, 135, 84, 115, 198, 104, 142, 135, 66, 165, 103, 110, 201, 103, 254, 92, 240, 147, 160, 27, 200, 251, 7, 163, 224, 108, 77, 71}
)

func main() {

	secretKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(signingKeyByte)
	if err != nil {
		log.Fatalf("Failed to create secret key: %v", err)
	}

	log.Println("secretKey: ", secretKey)

	conn, accountClient := setupAccountServiceClient(accountServer)
	defer conn.Close()

	authServer := newAuthServer(accountClient, secretKey)
	startGRPCServer(listenPort, authServer)
}

func setupAccountServiceClient(serverAddr string) (*grpc.ClientConn, proto.AccountServiceClient) {
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to account service at %s: %v", serverAddr, err)
	}
	return conn, proto.NewAccountServiceClient(conn)
}

func newAuthServer(accountClient proto.AccountServiceClient, secretKey paseto.V4AsymmetricSecretKey) *AuthServer {
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
	s := grpc.NewServer(
		grpc.UnaryInterceptor(utils.LoggingInterceptor()), // Unary Interceptor 추가
	)
	proto.RegisterAuthServiceServer(s, authServer)
	reflection.Register(s)
	log.Printf("Starting gRPC server on %s", listenAddr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC server over %s: %v", listenAddr, err)
	}
}

type AuthServer struct {
	proto.UnimplementedAuthServiceServer
	accountClient proto.AccountServiceClient
	secretKey     paseto.V4AsymmetricSecretKey
}

// Auth provider 유형과 provider 유저 아이디로 account 정보를 찾아서 JWT 토큰을 발급한다.
func (s *AuthServer) Auth(ctx context.Context, req *proto.AuthReq) (*proto.AuthResp, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request is nil")
	}

	accountResp, err := s.accountClient.GetAccountByProvider(ctx, &proto.GetAccountByProviderReq{
		Provider:       req.Provider,
		ProviderUserId: req.ProviderUserId,
	})

	var account *proto.Account

	if err != nil {
		if status.Code(err) == codes.NotFound {
			// 계정이 없으면 계정 생성
			createAccountResp, err := s.accountClient.CreateAccount(ctx, &proto.CreateAccountReq{
				Provider:       req.Provider,
				ProviderUserId: req.ProviderUserId,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "Error: %v", err)
			}
			account = createAccountResp.Account
		} else {
			return nil, status.Errorf(codes.Internal, "Error: %v", err)
		}
	} else {
		account = accountResp.Account
	}

	access_token, err := s.generateAccessToken(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate access token: %v", err)
	}

	refresh_token, err := s.generateRefreshToken(account.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate refresh token: %v", err)
	}

	return &proto.AuthResp{
		AccessToken:  access_token,
		RefreshToken: refresh_token,
		Account:      account,
	}, nil
}

func (s *AuthServer) AuthValidation(ctx context.Context, req *proto.AuthValidationReq) (*proto.AuthValidationResp, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request is nil")
	}

	_, err := s.validateToken(req.Token)
	if err != nil {
		return &proto.AuthValidationResp{
			Valid: false,
			Error: err.Error(),
		}, nil
	}

	return &proto.AuthValidationResp{
		Valid: true,
		Error: "",
	}, nil
}

func (s *AuthServer) generateAccessToken(account *proto.Account) (string, error) {
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

func (s *AuthServer) GetAccountByToken(ctx context.Context, req *proto.GetAccountByTokenReq) (*proto.GetAccountByTokenResp, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request is nil")
	}

	token, err := s.validateToken(req.Token)
	if err != nil {
		return nil, err
	}

	claims, err := decodeToken(token)
	if err != nil {
		return nil, err
	}

	id := claims["id"].(string)

	// account 정보를 가져온다.
	accountResp, err := s.accountClient.GetAccount(ctx, &proto.GetAccountReq{
		AccountId: id,
	})

	if err != nil {
		return nil, err
	}

	// account 정보가 없으면 인증 실패 처리
	if accountResp.Account == nil {
		return &proto.GetAccountByTokenResp{
			Account: nil,
		}, nil
	}

	return &proto.GetAccountByTokenResp{
		Account: accountResp.Account,
	}, nil
}

func (s *AuthServer) validateToken(tokenString string) (*paseto.Token, error) {
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
			return nil, err
		}
	}

	return token, nil
}

func decodeToken(token *paseto.Token) (map[string]interface{}, error) {
	claims := make(map[string]interface{})

	// 토큰의 모든 클레임을 순회하면서 map에 저장
	for key, value := range token.Claims() {
		claims[key] = value
	}

	return claims, nil
}

// auth/login
func (s *AuthServer) AuthCheckAccount(ctx context.Context, req *proto.AuthCheckAccountReq) (*proto.AuthCheckAccountResp, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "Request is nil")
	}
	token, err := s.validateToken(req.Token)
	if err != nil {
		return nil, err
	}

	claims, err := decodeToken(token)
	if err != nil {
		return nil, err
	}

	// claims에서 필요한 값을 가져옴

	provider := claims["provider"].(string)
	providerUserId := claims["providerUserId"].(string)

	accountResp, err := s.accountClient.GetAccountByProvider(ctx, &proto.GetAccountByProviderReq{
		Provider:       provider,
		ProviderUserId: providerUserId,
	})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "not exist account")
	}

	return &proto.AuthCheckAccountResp{Account: accountResp.Account}, nil
}
