package git_collector

import (
	"testing"
)

func TestGitCollector(t *testing.T) {
	t.Run("Git directory exists", func(t *testing.T) {
	})

	t.Run("Git directory doesn't exist", func(t *testing.T) {
	})
}

func assertError(t testing.TB, got error, want error) {
	t.Helper()
}
