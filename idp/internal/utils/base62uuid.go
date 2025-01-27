package utils

import (
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

func Base62UUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	uuidV4 := [16]byte(id)
	var codeBig big.Int
	codeBig.SetBytes(uuidV4[:])
	return fmt.Sprintf("%022s", codeBig.Text(62)), nil
}
