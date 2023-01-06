package server

import (
	"context"
	"fmt"

	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/server/db"
	"github.com/guacsec/guac/pkg/collectsub/server/db/simpledb"
	"google.golang.org/grpc"
)

type server struct {
	db db.CollectSubscriberDb
}

func NewServer() (*server, error) {
	db, err := simpledb.NewSimpleDb()
	if err != nil {
		return nil, err
	}

	return &server{
		db: db,
	}, nil
}

func (s *server) AddCollectEntry(ctx context.Context, in *pb.AddCollectEntriesRequest, opts ...grpc.CallOption) (*pb.AddCollectEntriesResponse, error) {
	err := s.db.AddCollectEntries(ctx, in.Entries)
	if err != nil {
		return nil, fmt.Errorf("failed to add entry to db: %w", err)
	}

	return &pb.AddCollectEntriesResponse{
		Success: true,
	}, nil
}

func (s *server) GetCollectEntries(ctx context.Context, in *pb.GetCollectEntriesRequest, opts ...grpc.CallOption) (*pb.GetCollectEntriesResponse, error) {
	ret, err := s.db.GetCollectEntries(ctx, in.Filters)
	if err != nil {
		return nil, fmt.Errorf("failed to get collect entries from db: %w", err)
	}
	return &pb.GetCollectEntriesResponse{
		Entries: ret,
	}, nil
}

func (s *server) GetCollectStatus(ctx context.Context, in *pb.GetCollectStatusRequest, opts ...grpc.CallOption) (*pb.GetCollectStatusResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}
