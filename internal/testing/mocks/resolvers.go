package mocks

import context "context"

type MockResolver struct {
	ResolveFunc func(context.Context) (interface{}, error)
}

func (m *MockResolver) Resolver(ctx context.Context) (interface{}, error) {
	return m.ResolveFunc(ctx)
}
