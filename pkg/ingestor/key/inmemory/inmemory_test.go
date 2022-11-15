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

package inmemory

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/keyutil"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func Test_inmemory_RetrieveKey(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider, pubKey := setupProvider(t)
	provider.collector["ecdsa"] = pubKey[0]
	provider.collector["rsa"] = pubKey[1]
	provider.collector["ed25519"] = pubKey[2]
	tests := []struct {
		name    string
		id      string
		want    *key.Key
		wantErr bool
	}{{
		name:    "get ecdsa key",
		id:      "ecdsa",
		want:    pubKey[0],
		wantErr: false,
	}, {
		name:    "get rsa key",
		id:      "rsa",
		want:    pubKey[1],
		wantErr: false,
	}, {
		name:    "get ed25519 key",
		id:      "ed25519",
		want:    pubKey[2],
		wantErr: false,
	}, {
		name:    "not found",
		id:      "findme",
		want:    nil,
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := provider.RetrieveKey(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("inmemory.RetrieveKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("inmemory.RetrieveKey() = %v, want %v", got, tt.want)
			}
			if !strings.Contains(string(provider.Type()), "inmemory") {
				t.Error("inmemory.Type() failed to return proper type")
			}
		})
	}
}

func Test_inmemory_StoreKey(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider, pubKey := setupProvider(t)
	type args struct {
		id string
		pk *key.Key
	}
	tests := []struct {
		name    string
		args    args
		want    *key.Key
		wantErr bool
	}{{
		name: "store ecdsa",
		args: args{
			id: "ecdsa",
			pk: pubKey[0],
		},
		want:    pubKey[0],
		wantErr: false,
	}, {
		name: "store rsa",
		args: args{
			id: "rsa",
			pk: pubKey[1],
		},
		want:    pubKey[1],
		wantErr: false,
	}, {
		name: "store ed25519",
		args: args{
			id: "ed25519",
			pk: pubKey[2],
		},
		want:    pubKey[2],
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.StoreKey(ctx, tt.args.id, tt.args.pk)
			if (err != nil) != tt.wantErr {
				t.Errorf("inmemory.StoreKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				got, _ := provider.RetrieveKey(ctx, tt.args.id)
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("inmemory.RetrieveKey() = %v, expected %v", got, tt.want)
				}
			}
		})
	}
}

func Test_inmemory_DeleteKey(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider, pubKey := setupProvider(t)
	provider.collector["ecdsa"] = pubKey[0]
	provider.collector["rsa"] = pubKey[1]
	provider.collector["ed25519"] = pubKey[2]
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{{
		name:    "delete ecdsa",
		id:      "ecdsa",
		wantErr: false,
	}, {
		name:    "delete rsa",
		id:      "rsa",
		wantErr: false,
	}, {
		name:    "delete ed25519",
		id:      "ed25519",
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.DeleteKey(ctx, tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("inmemory.DeleteKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if _, found := provider.collector[tt.id]; found {
					t.Errorf("inmemory.DeleteKey() failed as key still found")
				}
			}
		})
	}
}

func setupProvider(t *testing.T) (*inmemory, []*key.Key) {
	ecdsaPub, _, err := keyutil.GetECDSAPubKey()
	if err != nil {
		t.Fatalf("failed to get ecdsa key. Error: %v", err)
	}
	rsaPub, _, err := keyutil.GetRSAPubKey()
	if err != nil {
		t.Fatalf("failed to get rsa key. Error: %v", err)
	}
	ed25519Pub, _, err := keyutil.GetED25519Pub()
	if err != nil {
		t.Fatalf("failed to get ed25519 key. Error: %v", err)
	}

	keyHash, err := dsse.SHA256KeyID(ecdsaPub)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	ecdsaKey := &key.Key{
		Hash:   keyHash,
		Type:   "ecdsa",
		Val:    ecdsaPub,
		Scheme: "ecdsa-sha2-nistp256",
	}

	keyHash, err = dsse.SHA256KeyID(rsaPub)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	rsaKey := &key.Key{
		Hash:   keyHash,
		Type:   "rsa",
		Val:    rsaPub,
		Scheme: "rsassa-pss-sha256",
	}

	keyHash, err = dsse.SHA256KeyID(ed25519Pub)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	ed25519Key := &key.Key{
		Hash:   keyHash,
		Type:   "ed25519",
		Val:    ed25519Pub,
		Scheme: "ed25519",
	}

	provider := newInmemoryProvider()

	return provider, []*key.Key{ecdsaKey, rsaKey, ed25519Key}
}
