package backend

func ptr[T any](s T) *T {
	return &s
}
