//
// Copyright 2022 The AFF Authors.
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

package inmemory

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/key"
	"github.com/guacsec/guac/pkg/testutils"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Taken from: https://github.com/in-toto/in-toto-golang/blob/fa494aaa0add184054d127bb3fa25ca260723551/in_toto/keylib.go
/*
generateKeyID creates a partial key map and generates the key ID
based on the created partial key map via the SHA256 method.
The resulting keyID will be directly saved in the corresponding key object.
On success generateKeyID will return nil, in case of errors while encoding
there will be an error.
*/
func generateKeyID(k *in_toto.Key) error {
	// Create partial key map used to create the keyid
	// Unfortunately, we can't use the Key object because this also carries
	// yet unwanted fields, such as KeyID and KeyVal.Private and therefore
	// produces a different hash. We generate the keyID exactly as we do in
	// the securesystemslib  to keep interoperability between other in-toto
	// implementations.
	var keyToBeHashed = map[string]interface{}{
		"keytype":               k.KeyType,
		"scheme":                k.Scheme,
		"keyid_hash_algorithms": k.KeyIDHashAlgorithms,
		"keyval": map[string]string{
			"public": k.KeyVal.Public,
		},
	}
	keyCanonical, err := cjson.EncodeCanonical(keyToBeHashed)
	if err != nil {
		return err
	}
	// calculate sha256 and return string representation of keyID
	keyHashed := sha256.Sum256(keyCanonical)
	k.KeyID = fmt.Sprintf("%x", keyHashed)
	return nil
}

func getInTotoKey(c crypto.PublicKey) in_toto.Key {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(c)
	if err != nil {
		panic(err)
	}

	k := in_toto.Key{}
	pemData, _ := pem.Decode(pemBytes)
	if pemData == nil {
		panic("No PEM Block")
	}

	k.LoadKeyReaderDefaults(strings.NewReader(string(pemData.Bytes)))
	generateKeyID(&k)

	return k
}

func getKeyMap() key.KeyMap {
	c := testutils.GetDSSEExampleKey()
	k := getInTotoKey(c)
	return key.KeyMap{
		k.KeyID: c,
	}
}

func TestInMemoryKeyProvider_GetKey(t *testing.T) {
	m := getKeyMap()
	k := testutils.GetDSSEExampleKey()
	i := getInTotoKey(k)
	type fields struct {
		keyMap key.KeyMap
	}
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{
			name: "Key Found",
			fields: fields{
				keyMap: m,
			},
			args: args{
				id: i.KeyID,
			},
			want:    k,
			wantErr: false,
		},
		{
			name: "No Key Found",
			fields: fields{
				keyMap: m,
			},
			args: args{
				id: "id_none",
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &InMemoryKeyProvider{
				keyMap: tt.fields.keyMap,
			}
			got, err := i.GetKey(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("InMemoryKeyProvider.GetKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InMemoryKeyProvider.GetKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInMemoryKeyProvider_PutKey(t *testing.T) {
	m := getKeyMap()
	k := testutils.GetDSSEExampleKey()
	i := getInTotoKey(k)
	type fields struct {
		keyMap key.KeyMap
	}
	type args struct {
		id string
		pk crypto.PublicKey
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Put New Key Empty Map",
			fields: fields{
				keyMap: key.KeyMap{},
			},
			args: args{
				id: i.KeyID,
				pk: k,
			},
			wantErr: false,
		},
		{
			name: "Put Same Key",
			fields: fields{
				keyMap: m,
			},
			args: args{
				id: i.KeyID,
				pk: k,
			},
			wantErr: false,
		},
		{
			name: "Put New Key Existing Map",
			fields: fields{
				keyMap: m,
			},
			args: args{
				id: "newid",
				pk: k,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &InMemoryKeyProvider{
				keyMap: tt.fields.keyMap,
			}
			if err := i.PutKey(tt.args.id, tt.args.pk); (err != nil) != tt.wantErr {
				t.Errorf("InMemoryKeyProvider.PutKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !i.keyMap[tt.args.id].(*ecdsa.PublicKey).Equal(k) {
				t.Errorf("InMemoryKeyProvider.PutKey() keyMap = %v, want %v", i.keyMap, m)
			}
		})
	}
}

func TestInMemoryKeyProvider_DeleteKey(t *testing.T) {
	m := getKeyMap()
	k := testutils.GetDSSEExampleKey()
	i := getInTotoKey(k)
	type fields struct {
		keyMap key.KeyMap
	}
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Delete Existing Key",
			fields: fields{
				keyMap: m,
			},
			args: args{
				id: i.KeyID,
			},
			wantErr: false,
		},
		{
			name: "No Key Found",
			fields: fields{
				keyMap: m,
			},
			args: args{
				id: "non-existant",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &InMemoryKeyProvider{
				keyMap: tt.fields.keyMap,
			}
			if err := i.DeleteKey(tt.args.id); (err != nil) != tt.wantErr {
				t.Errorf("InMemoryKeyProvider.DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.name == "Delete Existing Key" {
				if _, exists := tt.fields.keyMap[tt.args.id]; exists {
					t.Errorf("InMemoryKeyProvider.DeleteKey() key %v shouldn't exist, keyMap: %v", tt.args.id, tt.fields.keyMap)
				}
			}
		})
	}
}
