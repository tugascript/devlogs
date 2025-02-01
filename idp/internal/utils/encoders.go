package utils

import (
	"math/big"
)

func Base62Encode(bytes []byte) string {
	var codeBig big.Int
	codeBig.SetBytes(bytes)
	return codeBig.Text(62)
}
