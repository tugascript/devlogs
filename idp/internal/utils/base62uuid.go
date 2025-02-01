package utils

import (
	"fmt"
	"github.com/google/uuid"
)

func Base62UUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%022s", Base62Encode(id[:])), nil
}
