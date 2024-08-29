//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package clients

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/logging"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// Define request and response messages
type testRequest struct{}
type testResponse struct{}

// Implement proto.Message interface for testRequest
func (m *testRequest) Reset()         {}
func (m *testRequest) String() string { return "testRequest" }
func (m *testRequest) ProtoMessage()  {}

// Implement proto.Message interface for testResponse
func (m *testResponse) Reset()         {}
func (m *testResponse) String() string { return "testResponse" }
func (m *testResponse) ProtoMessage()  {}

// Define a simple gRPC service
type testServerImpl struct {
}

func (s *testServerImpl) testMethod(ctx context.Context, req *testRequest) (*testResponse, error) {
	return &testResponse{}, nil
}

// Define the service interface
type testServiceServer interface {
	testMethod(context.Context, *testRequest) (*testResponse, error)
}

// registerTestServer registers the testServiceServer to the gRPC server.
func registerTestServer(s *grpc.Server, srv testServiceServer) {
	s.RegisterService(&_SimpleService_serviceDesc, srv)
}

var _SimpleService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "testService",
	HandlerType: (*testServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "testMethod",
			Handler:    testServiceTestMethodHandler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "test_service.proto",
}

func testServiceTestMethodHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(testRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testServiceServer).testMethod(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/testService/testMethod",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(testServiceServer).testMethod(ctx, req.(*testRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func TestRateLimitedClient(t *testing.T) {
	// Set up the logger
	var logBuffer bytes.Buffer
	encoderConfig := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(&logBuffer),
		zap.DebugLevel,
	)
	logger := zap.New(core).Sugar()

	ctx := context.Background()
	ctx = context.WithValue(ctx, logging.ChildLoggerKey, logger)

	// Set up the in-memory gRPC server
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	registerTestServer(s, &testServerImpl{})
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()
	defer s.Stop()

	// Create a connection to the in-memory gRPC server
	conn, err := grpc.NewClient("bufnet", grpc.WithContextDialer(
		func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.NoError(t, err)
	defer conn.Close()

	// Create a new rate-limited client
	limiter := rate.NewLimiter(rate.Every(time.Second*10), 10) // 10 requests per 10 seconds
	rateLimitedClient := NewRateLimitedClient(conn, limiter)

	logBuffer.Reset()

	// Make 11 calls to test rate limiting
	for i := 0; i < 11; i++ {
		_ = rateLimitedClient.Invoke(ctx, "/testService/testMethod", &testRequest{}, &testResponse{})
	}

	logOutput := logBuffer.String()

	// Check if the log contains the rate limit exceeded message
	assert.Contains(t, logOutput, "Rate limit exceeded for method")
}
