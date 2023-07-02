package backend

import (
	"strings"

	"github.com/google/go-cmp/cmp"
)

func ptr[T any](s T) *T {
	return &s
}

var ignoreID = cmp.FilterPath(func(p cmp.Path) bool {
	return strings.Compare(".ID", p[len(p)-1].String()) == 0
}, cmp.Ignore())
