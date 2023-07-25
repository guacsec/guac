//
// Copyright 2023 The GUAC Authors.
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

package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/server/db/simpledb"
	db "github.com/guacsec/guac/pkg/collectsub/server/db/types"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type server struct {
	pb.UnimplementedColectSubscriberServiceServer

	// Db points to the backend DB, public for mocking testing purposes.
	Db   db.CollectSubscriberDb
	port int
}

func NewServer(port int) (*server, error) {
	db, err := simpledb.NewSimpleDb()
	if err != nil {
		return nil, err
	}

	return &server{
		Db:   db,
		port: port,
	}, nil
}

func (s *server) AddCollectEntries(ctx context.Context, in *pb.AddCollectEntriesRequest) (*pb.AddCollectEntriesResponse, error) {
	logger := ctxzap.Extract(ctx).Sugar()
	logger.Infof("AddCollectEntries called with entries: %v", in.Entries)

	err := s.Db.AddCollectEntries(ctx, in.Entries)
	if err != nil {
		return nil, fmt.Errorf("failed to add entry to db: %w", err)
	}

	return &pb.AddCollectEntriesResponse{
		Success: true,
	}, nil
}

func (s *server) GetCollectEntries(ctx context.Context, in *pb.GetCollectEntriesRequest) (*pb.GetCollectEntriesResponse, error) {
	logger := ctxzap.Extract(ctx).Sugar()
	logger.Infof("GetCollectEntries called with filters: %v", in.Filters)

	ret, err := s.Db.GetCollectEntries(ctx, in.Filters, in.SinceTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get collect entries from db: %w", err)
	}
	logger.Infof("GetCollectEntries returning %d entries", len(ret))

	return &pb.GetCollectEntriesResponse{
		Entries: ret,
	}, nil
}

func ContextPropagationUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			ctx = metadata.NewOutgoingContext(ctx, md)
		}
		return handler(ctx, req)
	}
}

func ContextToZapFieldsUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			for k, v := range md {
				ctxzap.AddFields(ctx, zap.Strings(k, v))
			}
		}
		return handler(ctx, req)
	}
}

func (s *server) Serve(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("error opening port %d when starting csub server: %w", s.port, err)
	}
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				ContextPropagationUnaryServerInterceptor(),
				grpc_zap.UnaryServerInterceptor(logger.Desugar()),
				ContextToZapFieldsUnaryServerInterceptor(),
			)),
	}
	gs := grpc.NewServer(opts...)

	pb.RegisterColectSubscriberServiceServer(gs, s)

	var wg sync.WaitGroup
	var retErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("server listening at %v", lis.Addr())
		if err := gs.Serve(lis); err != nil {
			retErr = fmt.Errorf("csub grpc server error: %w", err)
		}
	}()
	<-ctx.Done()
	logger.Infof("context cancelled, gracefully shutting down csub grpc server")
	done := make(chan bool, 1)
	go func() {
		gs.GracefulStop()
		wg.Wait()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logger.Warnf("forcibly shutting down csub grpc server")
		gs.Stop()
	}
	wg.Wait()
	return retErr
}
