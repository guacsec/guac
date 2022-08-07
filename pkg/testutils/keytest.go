package testutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

// This key is based on this example:
// https://github.com/secure-systems-lab/dsse/blob/31569a75dbe2b956f27b510394f5ff82a9958ec2/protocol.md
// implemented here:
// https://github.com/secure-systems-lab/go-securesystemslib/blob/c1e41ba5f168bb0cecaac7ce1bbe787c20e72d9b/dsse/sign_test.go
func GetDSSEExampleKey() *ecdsa.PublicKey {
	x := new(big.Int)
	y := new(big.Int)

	if _, ok := x.SetString("46950820868899156662930047687818585632848591499744589407958293238635476079160", 10); !ok {
		return nil
	}
	if _, ok := y.SetString("5640078356564379163099075877009565129882514886557779369047442380624545832820", 10); !ok {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
}
