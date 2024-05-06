package utils

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
)

// LoggingInterceptor는 gRPC 서버의 요청 및 응답을 로깅하는 인터셉터입니다.
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	// 로그 파일 핸들러 생성
	logFile := getgRPCLogFileWriter()
	defer logFile.Close()

	// 로그 파일 핸들러와 표준 출력 핸들러를 모두 사용하는 로거 설정
	logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		logger.Printf("Received request: %s", info.FullMethod)
		logger.Printf("Request: %v", req)

		// 서버 핸들러 호출
		resp, err := handler(ctx, req)

		if err != nil {
			logger.Printf("Error: %v", err)
		} else {
			logger.Printf("Responding with: %v", resp)
		}

		return resp, err
	}
}

// getgRPCLogFileWriter 함수는 로그 파일을 생성하고 반환합니다.
func getgRPCLogFileWriter() *os.File {
	// 로그 폴더 생성
	logFolder := "log"
	if err := os.MkdirAll(logFolder, os.ModePerm); err != nil {
		log.Fatalf("[E-1al] failed to create log folder: %v", err)
	}

	// 로그 파일 생성
	logFile := filepath.Join(logFolder, time.Now().Format("2006-01-02")+"_gRPC.log")
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("[E-xgk] failed to open log file: %v", err)
	}
	return file
}
