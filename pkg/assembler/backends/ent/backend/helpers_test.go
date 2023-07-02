package backend

import (
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
)

func ptr[T any](s T) *T {
	return &s
}

var ignoreID = cmp.FilterPath(func(p cmp.Path) bool {
	return strings.Compare(".ID", p[len(p)-1].String()) == 0
}, cmp.Ignore())

var ignoreEmptySlices = cmp.FilterValues(func(x, y interface{}) bool {
	xv, yv := reflect.ValueOf(x), reflect.ValueOf(y)
	if xv.Kind() == reflect.Slice && yv.Kind() == reflect.Slice {
		return xv.Len() == 0 && yv.Len() == 0
	}
	return false
}, cmp.Ignore())
