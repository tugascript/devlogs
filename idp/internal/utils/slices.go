package utils

func MapSlice[T any, U any](s []T, f func(*T) U) []U {
	result := make([]U, len(s))

	for i, v := range s {
		result[i] = f(&v)
	}

	return result
}

func MapSliceWithErr[T any, U any, E error](s []T, f func(*T) (U, E)) ([]U, E) {
	result := make([]U, 0, len(s))

	for _, v := range s {
		mv, err := f(&v)
		if err != nil {
			return nil, err
		}

		result = append(result, mv)
	}

	var err E
	return result, err
}
