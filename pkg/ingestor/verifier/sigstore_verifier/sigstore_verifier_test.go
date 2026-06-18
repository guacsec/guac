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

package sigstore_verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

// PayloadType is the in-toto DSSE payload type.
const PayloadType = "application/vnd.in-toto+json"

// StatementInTotoV01 is the in-toto v0.1 statement type.
// Mirrors the canonical upstream type URI from github.com/in-toto/in-toto-golang.
const StatementInTotoV01 = "https://in-toto.io/Statement/v0.1"

// predicateSLSAProvenanceV02 is the predicate type for SLSAv0.2 provenance.
// Mirrors parser_slsa.PredicateSLSAProvenanceV02.
const predicateSLSAProvenanceV02 = "https://slsa.dev/provenance/v0.2"

// digestSet is a set of digests keyed by algorithm name (e.g. "sha256").
// Mirrors the DigestSet type from github.com/in-toto/in-toto-golang/in_toto.
type digestSet = map[string]string

// provenanceBuilder identifies the entity that executed the build steps.
// Mirrors the ProvenanceBuilder type from github.com/in-toto/in-toto-golang/in_toto
// with the same JSON field name to ensure the test exercises the correct wire format.
type provenanceBuilder struct {
	ID string `json:"id"`
}

// subject describes the set of software artifacts the statement applies to.
// Mirrors the Subject type from github.com/in-toto/in-toto-golang/in_toto
// with the same JSON field names to ensure the test exercises the correct wire format.
type subject struct {
	Name   string    `json:"name"`
	Digest digestSet `json:"digest"`
}

// statementHeader defines the common fields for all in-toto v0.1 statements.
// Mirrors the StatementHeader type from github.com/in-toto/in-toto-golang/in_toto
// with identical JSON tags (_type, predicateType, subject) to exercise the
// exact wire format the verifier processes in production.
type statementHeader struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subject       []subject `json:"subject"`
}

// provenancePredicate is the SLSA v0.2 provenance predicate.
// Mirrors the ProvenancePredicate type from github.com/in-toto/in-toto-golang/in_toto
// (simplified to only the fields needed for signing/verification testing).
type provenancePredicate struct {
	Builder provenanceBuilder `json:"builder"`
}

// provenanceStatement is the complete in-toto v0.1 provenance statement.
// Mirrors the ProvenanceStatement type from github.com/in-toto/in-toto-golang/in_toto
// with the same embedded statementHeader and JSON field names to ensure
// the test exercises the exact format the verifier consumes in production.
type provenanceStatement struct {
	statementHeader
	Predicate provenancePredicate `json:"predicate"`
}

type mockKeyProvider struct {
	collector map[string]key.Key
}

func newMockProvider() *mockKeyProvider {
	return &mockKeyProvider{
		collector: map[string]key.Key{},
	}
}

func (m *mockKeyProvider) RetrieveKey(ctx context.Context, id string) (*key.Key, error) {
	if key, ok := m.collector[id]; ok {
		return &key, nil
	}
	return nil, nil
}

func (m *mockKeyProvider) StoreKey(ctx context.Context, id string, pk *key.Key) error {
	m.collector[id] = *pk
	return nil
}

func (m *mockKeyProvider) DeleteKey(ctx context.Context, id string) error {
	delete(m.collector, id)
	return nil
}

func (m *mockKeyProvider) Type() key.KeyProviderType {
	return "mock"
}

func setupOneProvider(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	provider := newMockProvider()
	err := key.RegisterKeyProvider(provider, "mock")
	if err != nil {
		t.Log(err)
	}

	err = key.Store(ctx, ecdsaKeyID, []byte(ecdsaPub), "mock")
	if err != nil {
		t.Fatal("failed to store into mock key provider")
	}
	err = key.Store(ctx, rsaKeyID, []byte(rsapub), "mock")
	if err != nil {
		t.Fatal("failed to store into mock key provider")
	}
}

func randomData(t *testing.T, n int) []byte {
	t.Helper()
	gen := rand.New(rand.NewSource(time.Now().UnixNano()))
	data := make([]byte, n)
	if _, err := gen.Read(data[:]); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSigstoreVerifier_Verify(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	setupOneProvider(t)
	d := randomData(t, 10)
	id := base64.StdEncoding.EncodeToString(d)

	it := provenanceStatement{
		statementHeader: statementHeader{
			Type:          StatementInTotoV01,
			PredicateType: predicateSLSAProvenanceV02,
			Subject: []subject{
				{
					Name: "foobar",
					Digest: digestSet{
						"foo": "bar",
					},
				},
			},
		},
		Predicate: provenancePredicate{
			Builder: provenanceBuilder{
				ID: "foo" + id,
			},
		},
	}

	b, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}

	pb, _ := pem.Decode([]byte(ecdsaPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	dsseSigner := dsse.WrapSigner(signer, PayloadType)

	env, err := dsseSigner.SignMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}

	envDSSE, err := parseDSSE(env)
	if err != nil {
		t.Fatal(err)
	}
	envDSSE.Signatures[0].KeyID = ecdsaKeyID
	env, err = json.Marshal(envDSSE)
	if err != nil {
		t.Fatal(err)
	}
	doc := &processor.Document{
		Blob:              env,
		Type:              processor.DocumentDSSE,
		Format:            processor.FormatJSON,
		SourceInformation: processor.SourceInformation{},
	}

	envDSSE.Signatures[0].KeyID = rsaKeyID
	env, err = json.Marshal(envDSSE)
	if err != nil {
		t.Fatal(err)
	}
	badDoc := &processor.Document{
		Blob:              env,
		Type:              processor.DocumentDSSE,
		Format:            processor.FormatJSON,
		SourceInformation: processor.SourceInformation{},
	}

	tests := []struct {
		name    string
		doc     *processor.Document
		want    []verifier.Identity
		wantErr bool
	}{{
		name:    "verify Document",
		doc:     doc,
		want:    []verifier.Identity{},
		wantErr: false,
	}, {
		name:    "unverified Document",
		doc:     badDoc,
		want:    []verifier.Identity{},
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigVerifier := NewSigstoreAndKeyVerifier()
			got, err := sigVerifier.Verify(ctx, tt.doc.Blob)
			if (err != nil) != tt.wantErr {
				t.Errorf("SigstoreVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("SigstoreVerifier.Verify() = %v, want %v", got, tt.want)
				}
			}
			if sigVerifier.Type() != "sigstore" {
				t.Errorf("sigVerifier.Type() = %s, want %s", sigVerifier.Type(), "sigstore")
			}
		})
	}
}

func TestMultiSignatureSigstoreVerifier_Verify(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	setupOneProvider(t)
	// Get some random data so it's unique each run
	d := randomData(t, 10)
	id := base64.StdEncoding.EncodeToString(d)

	it := provenanceStatement{
		statementHeader: statementHeader{
			Type:          StatementInTotoV01,
			PredicateType: predicateSLSAProvenanceV02,
			Subject: []subject{
				{
					Name: "foobar",
					Digest: digestSet{
						"foo": "bar",
					},
				},
			},
		},
		Predicate: provenancePredicate{
			Builder: provenanceBuilder{
				ID: "foo" + id,
			},
		},
	}

	b, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}

	pb, _ := pem.Decode([]byte(ecdsaPriv))
	priv, err := x509.ParsePKCS8PrivateKey(pb.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signECDSA, err := signature.LoadECDSASigner(priv.(*ecdsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	pbRSA, _ := pem.Decode([]byte(rsaKey))
	rsaPriv, err := x509.ParsePKCS8PrivateKey(pbRSA.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	signRSA, err := signature.LoadRSAPKCS1v15Signer(rsaPriv.(*rsa.PrivateKey), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	dsseSigner := dsse.WrapMultiSigner(PayloadType, signECDSA, signRSA)

	env, err := dsseSigner.SignMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}

	doc := &processor.Document{
		Blob:              env,
		Type:              processor.DocumentDSSE,
		Format:            processor.FormatJSON,
		SourceInformation: processor.SourceInformation{},
	}

	tests := []struct {
		name    string
		doc     *processor.Document
		want    []verifier.Identity
		wantErr bool
	}{{
		name:    "verify Document",
		doc:     doc,
		want:    []verifier.Identity{},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigVerifier := NewSigstoreAndKeyVerifier()
			got, err := sigVerifier.Verify(ctx, tt.doc.Blob)
			if (err != nil) != tt.wantErr {
				t.Errorf("SigstoreVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("SigstoreVerifier.Verify() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

const (
	ecdsaKeyID = "SHA256:s9b/UAMASq9HN7RPBm5cIHQGoBOQA120kFdWLW/lT88"
	rsaKeyID   = "SHA256:843yiXZzbDfB0gA1snxYG5SISWMnDimw8/8Aew0nVNg"
	// Obtained from rekor e2e test. Generated with:
	// openssl ecparam -genkey -name prime256v1 > ec_private.pem
	// openssl pkcs8 -topk8 -in ec_private.pem  -nocrypt
	ecdsaPriv = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmrLtCpBdXgXLUr7o
nSUPfo3oXMjmvuwTOjpTulIBKlKhRANCAATH6KSpTFe6uXFmW1qNEFXaO7fWPfZt
pPZrHZ1cFykidZoURKoYXfkohJ+U/USYy8Sd8b4DMd5xDRZCnlDM0h37
-----END PRIVATE KEY-----`
	// Extracted from above with:
	// openssl ec -in ec_private.pem -pubout
	ecdsaPub = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx+ikqUxXurlxZltajRBV2ju31j32
baT2ax2dXBcpInWaFESqGF35KISflP1EmMvEnfG+AzHecQ0WQp5QzNId+w==
-----END PUBLIC KEY-----`
	rsaKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDfCoj9PKxSIpOB
jVvP7B0l8Q6KXgwSxEBIobMl11nrH2Fv6ufZRWgma7E3rZcjRMygyfia6SB8KBjq
OBMHnxX78tp5IDxbPWniA7GGTWZyBsXgfLFH7GVGBh8fiJJtfL4TP/xmMzY47rx8
qvglkQDktdmSEmvfYmof5SIXD/CBI9YDxpXQB9EBcd16QnjwHUKHElOs4lZI9OeP
8TSV8tWyskq1cO4LxPS8WZVTvbq0jp84OwQTpWtJqG/DUQ1QfMjfixt+uauCDA87
iIwBC+rC7aCfaXHpqNayHzToUi2Jc34O6LMyfHgowEjQgnKehClY4Vuy0aJXQvKB
mRDqyjO/AgMBAAECggEBAIHOAs3Gis8+WjRSjXVjh882DG1QsJwXZQYgPT+vpiAl
YjKdNpOHRkbd9ARgXY5kEuccxDd7p7E6MM3XFpQf7M51ltpZfWboRgAIgD+WOiHw
eSbdytr95C6tj11twTJBH+naGk1sTokxv7aaVdKfIjL49oeBexBFmVe4pW9gkmrE
1z1y1a0RohqbZ0kprYPWjz5UhsNqbCzgkdDqS7IrcOwVg6zvKYFjHnqIHqaJXVif
FgIfoNt7tz+12FTHI+6OkKoN3YCJueaxneBhITXm6RLOpQWa9qhdUPbkJ9vQNfph
Qqke4faaxKY9UDma+GpEHR016AWufZp92pd9wQkDn0kCgYEA7w/ZizAkefHoZhZ8
Isn/fYu4fdtUaVgrnGUVZobiGxWrHRU9ikbAwR7UwbgRSfppGiJdAMq1lyH2irmb
4OHU64rjuYSlIqUWHLQHWmqUbLUvlDojH/vdmH/Zn0AbrLZaimC5UCjK3Eb7sAMq
G0tGeDX2JraQvx7KrbC6peTaaaMCgYEA7tgZBiRCQJ7+mNu+gX9x6OXtjsDCh516
vToRLkxWc7LAbC9LKsuEHl4e3vy1PY/nyuv12Ng2dBq4WDXozAmVgz0ok7rRlIFp
w8Yj8o/9KuGZkD/7tw/pLsVc9Q3Wf0ACrnAAh7+3dAvn3yg+WHwXzqWIbrseDPt9
ILCfUoNDpzUCgYAKFCX8y0PObFd67lm/cbq2xUw66iNN6ay1BEH5t5gSwkAbksis
ar03pyAbJrJ75vXFZ0t6fBFZ1NG7GYYr3fmHEKz3JlN7+W/MN/7TXgjx6FWgLy9J
6ul1w3YeU6qXBn0ctmU5ru6WiNuVmRyOWAcZjFTbXvkNRbQPzJKh6dsXdwKBgA1D
FIihxMf/zBVCxl48bF/JPJqbm3GaTfFp4wBWHsrH1yVqrtrOeCSTh1VMZOfpMK60
0W7b+pIR1cCYJbgGpDWoVLN3QSHk2bGUM/TJB/60jilTVC/DA2ikbtfwj8N7E2sK
Lw1amN4ptxNOEcAqC8xepqe3XiDMahNBm2cigMQtAoGBAKwrXvss2BKz+/6poJQU
A0c7jhMN8M9Y5S2Ockw07lrQeAgfu4q+/8ztm0NeHJbk01IJvJY5Nt7bSgwgNVlo
j7vR2BMAc9U73Ju9aeTl/L6GqmZyA+Ojhl5gA5DPZYqNiqi93ydgRaI6n4+o3dI7
5wnr40AmbuKCDvMOvN7nMybL
-----END PRIVATE KEY-----`
	// Extracted from the certificate using:
	// openssl x509 -pubkey -noout -in test.crt
	rsapub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3wqI/TysUiKTgY1bz+wd
JfEOil4MEsRASKGzJddZ6x9hb+rn2UVoJmuxN62XI0TMoMn4mukgfCgY6jgTB58V
+/LaeSA8Wz1p4gOxhk1mcgbF4HyxR+xlRgYfH4iSbXy+Ez/8ZjM2OO68fKr4JZEA
5LXZkhJr32JqH+UiFw/wgSPWA8aV0AfRAXHdekJ48B1ChxJTrOJWSPTnj/E0lfLV
srJKtXDuC8T0vFmVU726tI6fODsEE6VrSahvw1ENUHzI34sbfrmrggwPO4iMAQvq
wu2gn2lx6ajWsh806FItiXN+DuizMnx4KMBI0IJynoQpWOFbstGiV0LygZkQ6soz
vwIDAQAB
-----END PUBLIC KEY-----`
)
