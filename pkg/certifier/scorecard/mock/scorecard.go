// Code generated by MockGen. DO NOT EDIT.
// Source: /Users/nathannaveen/go/src/github.com/nathannaveen/guac/pkg/certifier/scorecard/types.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	pkg "github.com/ossf/scorecard/v4/pkg"
)

// MockScorecard is a mock of Scorecard interface.
type MockScorecard struct {
	ctrl     *gomock.Controller
	recorder *MockScorecardMockRecorder
}

// MockScorecardMockRecorder is the mock recorder for MockScorecard.
type MockScorecardMockRecorder struct {
	mock *MockScorecard
}

// NewMockScorecard creates a new mock instance.
func NewMockScorecard(ctrl *gomock.Controller) *MockScorecard {
	mock := &MockScorecard{ctrl: ctrl}
	mock.recorder = &MockScorecardMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockScorecard) EXPECT() *MockScorecardMockRecorder {
	return m.recorder
}

// GetScore mocks base method.
func (m *MockScorecard) GetScore(repoName, commitSHA string) (*pkg.ScorecardResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetScore", repoName, commitSHA)
	ret0, _ := ret[0].(*pkg.ScorecardResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetScore indicates an expected call of GetScore.
func (mr *MockScorecardMockRecorder) GetScore(repoName, commitSHA interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetScore", reflect.TypeOf((*MockScorecard)(nil).GetScore), repoName, commitSHA)
}
