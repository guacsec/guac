package deps_dev

import (
	"context"

	pb "deps.dev/api/v3"
	"github.com/stretchr/testify/mock"
)

type MockInsightsServer struct {
	mock.Mock
	pb.UnimplementedInsightsServer
}

func (m *MockInsightsServer) GetProject(ctx context.Context, req *pb.GetProjectRequest) (*pb.Project, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*pb.Project), args.Error(1)
}
