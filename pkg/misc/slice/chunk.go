package slice

func Chunk[T any](slice []T, maxChunkSize int, cb func([]T) error) error {
	for start := 0; start < len(slice); start += maxChunkSize {
		end := start + maxChunkSize
		if end > len(slice) {
			end = len(slice)
		}

		if err := cb(slice[start:end]); err != nil {
			return err
		}
	}

	return nil
}
