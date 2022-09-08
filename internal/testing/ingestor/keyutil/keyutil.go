//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keyutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func GetECDSAPubKey() (crypto.PublicKey, []byte, error) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa.GenerateKey failed: %v", err)
	}
	pemBytes, err := GetPemBytes(ecdsaPriv.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
	}
	return ecdsaPriv.Public(), pemBytes, nil
}

func GetRSAPubKey() (crypto.PublicKey, []byte, error) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa.GenerateKey failed: %v", err)
	}
	pemBytes, err := GetPemBytes(rsaPriv.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
	}
	return rsaPriv.Public(), pemBytes, nil
}

func GetED25519Pub() (crypto.PublicKey, []byte, error) {
	edpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519.GenerateKey failed: %v", err)
	}
	pemBytes, err := GetPemBytes(edpub)
	if err != nil {
		return nil, nil, fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
	}
	return crypto.PublicKey(edpub), pemBytes, nil
}

func GetPemBytes(pub crypto.PublicKey) ([]byte, error) {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		return nil, fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
	}
	return pemBytes, nil
}
