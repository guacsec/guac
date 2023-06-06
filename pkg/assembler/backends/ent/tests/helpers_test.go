package tests

func ptr[T any](s T) *T {
	return &s
}
