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
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	cjson "github.com/docker/go/canonical/json"
	goapiruntime "github.com/go-openapi/runtime"
	jsoniter "github.com/json-iterator/go"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	proto_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorClient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	rekorGenClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/intoto"
	rverify "github.com/sigstore/rekor/pkg/verify"
	sigstoreFulcioCertificate "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sigstoreRoot "github.com/sigstore/sigstore-go/pkg/root"
	sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
	sigstoreVerify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	dsseverifier "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/slsa-framework/slsa-github-generator/signing/envelope"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/release-utils/version"

	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/logging"
	dsse_ssl "github.com/secure-systems-lab/go-securesystemslib/dsse"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	dsse_rekor "github.com/sigstore/rekor/pkg/types/dsse"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/sigstore/sigstore/pkg/signature"
	sig_dsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	defaultRekorAddr = "https://rekor.sigstore.dev"
)

var (
	defaultRekorClient     *rekorGenClient.Rekor
	defaultRekorClientOnce = new(sync.Once)
	json                   = jsoniter.ConfigCompatibleWithStandardLibrary
	certOidcIssuer         = "https://token.actions.githubusercontent.com"
	githubCom              = "github.com/"
	httpsGithubCom         = "https://" + githubCom
	certSubjectRegexp      = httpsGithubCom + "*"

	// cache the trusted root.
	trustedRoot *sigstoreRoot.LiveTrustedRoot
	// trustedRootOnce is used for initializing the trustedRoot.
	trustedRootOnce = new(sync.Once)
)

// SignedAttestation contains a signed DSSE envelope
// and its associated signing certificate.
type SignedAttestation struct {
	// The signed DSSE envelope
	Envelope *dsselib.Envelope
	// The signing certificate
	SigningCert *x509.Certificate
	// The associated verified Rekor entry
	RekorEntry *models.LogEntryAnon
	// The Public Key in the Bundle's VerificationMaterial
	PublicKey *proto_v1.PublicKeyIdentifier
}

type sigstoreVerifier struct {
	keyless bool
}

// SigstoreTUFClient is the interface for the Sigstore TUF client.
type SigstoreTUFClient interface {
	// GetTarget retrieves the target file from the TUF repository.
	GetTarget(target string) ([]byte, error)
}

// GetSigstoreTrustedRoot returns the trusted root for the Sigstore TUF client.
func getSigstoreTrustedRoot() (*sigstoreRoot.LiveTrustedRoot, error) {
	var err error
	trustedRootOnce.Do(func() {
		opts := sigstoreTUF.DefaultOptions()
		trustedRoot, err = sigstoreRoot.NewLiveTrustedRoot(opts)
		if err != nil {
			trustedRootOnce = new(sync.Once)
			return
		}
	})
	if err != nil {
		return nil, err
	}
	return trustedRoot, nil
}

// NewSigstoreVerifier initializes the sigstore verifier
func NewSigstoreAndKeyVerifier(keyless bool) *sigstoreVerifier {
	return &sigstoreVerifier{
		keyless: keyless,
	}
}

// Verify validates that the signature is valid for the payload
// TODO: this currently only supports SHA256 hash function when validating signatures
func (d *sigstoreVerifier) Verify(ctx context.Context, payloadBytes []byte, artifactHash string) ([]verifier.Identity, error) {

	if d.keyless {
		err := verifyArtifact(ctx, payloadBytes, "sha256:29b46bd09e2ff54f7f31cf8c1eed0925e70ff03ee46269714cea84c8cd7ed9da")
		if err != nil {
			return nil, fmt.Errorf("failed to verify artifact with error: %w", err)
		}
	} else {
		identities := []verifier.Identity{}
		envelope, err := parseDSSE(payloadBytes)
		if err != nil {
			return nil, err
		}
		for _, signature := range envelope.Signatures {
			key, err := key.Find(ctx, signature.KeyID)
			if err != nil {
				return nil, err
			}

			// currently keyID needs to be the hash of the public key
			// see:
			// https://github.com/sigstore/sigstore/blob/main/pkg/signature/dsse/dsse.go#L107
			// and
			// https://github.com/secure-systems-lab/go-securesystemslib/blob/main/dsse/verify.go#L69s
			/*foundIdentity := verifier.Identity{
				ID:  signature.KeyID,
				Key: *key,
			}*/
			err = verifySignature(key.Val, payloadBytes)
			if err != nil {
				// logging here as we don't want to fail but record that the signature check failed
				logger := logging.FromContext(ctx)
				logger.Errorf("failed to verify signature with provided key: %v", key.Hash)
				return nil, err
			}
			// if err (meaning that the keyID or the signature verification failed), verified is set to false
			/*foundIdentity.Verified = (err == nil)
			identities = append(identities, foundIdentity)*/
		}
		return identities, nil
	}
	return nil, nil
}

// getDefaultRekorClient returns a cached Rekor client.
func getDefaultRekorClient() (*rekorGenClient.Rekor, error) {
	var err error
	defaultRekorClientOnce.Do(func() {
		userAgent := fmt.Sprintf("slsa-verifier/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
		defaultRekorClient, err = rekorClient.GetRekorClient(defaultRekorAddr, rekorClient.WithUserAgent(userAgent))
		if err != nil {
			defaultRekorClientOnce = new(sync.Once)
			return
		}
	})
	if err != nil {
		return nil, err
	}
	return defaultRekorClient, nil
}

// isSigstoreBundle checks if the provenance is a Sigstore bundle.
func isSigstoreBundle(bytes []byte) bool {
	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bytes, &bundle); err != nil {
		return false
	}
	return true
}

// VerifyArtifact verifies provenance for an artifact.
func verifyArtifact(ctx context.Context,
	provenance []byte, artifactHash string,
) error {

	isSigstoreBundle := isSigstoreBundle(provenance)

	// This includes a default retry count of 3.
	rClient, err := getDefaultRekorClient()
	if err != nil {
		return err
	}

	trustedRoot, err := getSigstoreTrustedRoot()
	if err != nil {
		return err
	}

	/* Verify signature on the intoto attestation. */
	if isSigstoreBundle {
		_, err = verifyProvenanceBundle(ctx, provenance, trustedRoot)
	} else {
		_, err = VerifyProvenanceSignature(ctx, trustedRoot, rClient,
			provenance, artifactHash)
	}
	if err != nil {
		return err
	}
	return nil
}

// hasCertInEnvelope checks if a valid x509 certificate is present in the
// envelope.
func hasCertInEnvelope(provenance []byte) bool {
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	return err == nil && len(certPem) > 0
}

// VerifyProvenanceSignature returns the verified DSSE envelope containing the provenance
// and the signing certificate given the provenance and artifact hash.
func VerifyProvenanceSignature(ctx context.Context, trustedRoot *sigstoreRoot.LiveTrustedRoot,
	rClient *client.Rekor,
	provenance []byte, artifactHash string) (
	*SignedAttestation, error,
) {
	// There are two cases, either we have an embedded certificate, or we need
	// to use the Redis index for searching by artifact SHA.
	if hasCertInEnvelope(provenance) {
		// Get Rekor entries corresponding to provenance
		return GetValidSignedAttestationWithCert(rClient, provenance, trustedRoot)
	}

	// Fallback on using the redis search index to get matching UUIDs.
	fmt.Fprintf(os.Stderr, "No certificate provided, trying Redis search index to find entries by subject digest\n")

	// Verify the provenance and return the signing certificate.
	return SearchValidSignedAttestation(ctx, artifactHash,
		provenance, rClient, trustedRoot)
}

// getUUIDsByArtifactDigest finds all entry UUIDs by the digest of the artifact binary.
func getUUIDsByArtifactDigest(rClient *rekorGenClient.Rekor, artifactHash string) ([]string, error) {
	// Use search index to find rekor entry UUIDs that match Subject Digest.
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{Hash: fmt.Sprintf("sha256:%v", artifactHash)}
	resp, err := rClient.Index.SearchIndex(params)
	if err != nil {
		return nil, fmt.Errorf("rekor search error: %s", err.Error())
	}

	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("no matching entries found")
	}

	return resp.GetPayload(), nil
}

func verifyTlogEntryByUUID(ctx context.Context, client *rekorGenClient.Rekor,
	entryUUID string, trustedRoot *sigstoreRoot.LiveTrustedRoot) (
	*models.LogEntryAnon, error,
) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.EntryUUID = entryUUID

	lep, err := client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}

	if len(lep.Payload) != 1 {
		return nil, errors.New("UUID value can not be extracted")
	}

	uuid, err := sharding.GetUUIDFromIDString(params.EntryUUID)
	if err != nil {
		return nil, err
	}

	for k, entry := range lep.Payload {
		returnUUID, err := sharding.GetUUIDFromIDString(k)
		if err != nil {
			return nil, err
		}
		// Validate that the request matches the response
		if returnUUID != uuid {
			return nil, errors.New("expected matching UUID")
		}
		// Validate the entry response.
		return verifyTlogEntry(ctx, entry, true, trustedRoot)
	}

	return nil, fmt.Errorf("rekor search error")
}

func extractCert(e *models.LogEntryAnon) (*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), goapiruntime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *intoto_v001.V001Entry:
		publicKeyB64, err = e.IntotoObj.PublicKey.MarshalText()
	case *dsse_v001.V001Entry:
		if len(e.DSSEObj.Signatures) > 1 {
			return nil, errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		publicKeyB64, err = e.DSSEObj.Signatures[0].Verifier.MarshalText()
	default:
		return nil, errors.New("unexpected tlog entry type")
	}
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) != 1 {
		return nil, errors.New("unexpected number of cert pem tlog entry")
	}

	return certs[0], err
}

// SearchValidSignedAttestation searches for a valid signing certificate using the Rekor
// Redis search index by using the artifact digest.
func SearchValidSignedAttestation(ctx context.Context, artifactHash string, provenance []byte,
	rClient *rekorGenClient.Rekor, trustedRoot *sigstoreRoot.LiveTrustedRoot,
) (*SignedAttestation, error) {
	// Get Rekor UUIDs by artifact digest.
	uuids, err := getUUIDsByArtifactDigest(rClient, artifactHash)
	if err != nil {
		return nil, err
	}

	env, err := EnvelopeFromBytes(provenance)
	if err != nil {
		return nil, err
	}

	// Iterate through each matching UUID and perform:
	//   * Verify TLOG entry (inclusion and signed entry timestamp against Rekor pubkey).
	//   * Verify the signing certificate against the Fulcio root CA.
	//   * Verify dsse envelope signature against signing certificate.
	//   * Check signature expiration against IntegratedTime in entry.
	//   * If all succeed, return the signing certificate.
	var errs []string
	for _, uuid := range uuids {
		entry, err := verifyTlogEntryByUUID(ctx, rClient, uuid, trustedRoot)
		if err != nil {
			// this is unexpected, hold on to this error.
			errs = append(errs, fmt.Sprintf("%s: verifying tlog entry %s", err, uuid))
			continue
		}

		cert, err := extractCert(entry)
		if err != nil {
			// this is unexpected, hold on to this error.
			errs = append(errs, fmt.Sprintf("%s: extracting certificate from %s", err, uuid))
			continue
		}

		proposedSignedAtt := &SignedAttestation{
			Envelope:    env,
			SigningCert: cert,
			RekorEntry:  entry,
		}

		err = verifySignedAttestation(proposedSignedAtt, trustedRoot)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		// success!
		url := fmt.Sprintf("%v/%v/%v", defaultRekorAddr, "api/v1/log/entries", uuid)
		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at URL: %s\n", *entry.LogIndex, url)
		return proposedSignedAtt, nil
	}

	return nil, fmt.Errorf("no valid rekor entires: got unexpected errors %s", strings.Join(errs, ", "))
}

// GetValidSignedAttestationWithCert finds and validates the matching entry UUIDs with
// the full intoto attestation.
// The attestation generated by the slsa-github-generator libraries contain a signing certificate.
func GetValidSignedAttestationWithCert(rClient *rekorGenClient.Rekor,
	provenance []byte, trustedRoot *sigstoreRoot.LiveTrustedRoot,
) (*SignedAttestation, error) {
	// Use intoto attestation to find rekor entry UUIDs.
	params := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	if err != nil {
		return nil, fmt.Errorf("error getting certificate from provenance: %w", err)
	}

	intotoEntry, err := intotoEntry(certPem, provenance)
	if err != nil {
		return nil, fmt.Errorf("error creating intoto entry: %w", err)
	}
	dsseEntry, err := dsseEntry(certPem, provenance)
	if err != nil {
		return nil, err
	}
	searchLogQuery.SetEntries([]models.ProposedEntry{intotoEntry, dsseEntry})

	params.SetEntry(&searchLogQuery)
	resp, err := rClient.Entries.SearchLogQuery(params)
	if err != nil {
		return nil, fmt.Errorf("SearchLogQuery error: %s", err.Error())
	}

	if len(resp.GetPayload()) != 1 {
		return nil, fmt.Errorf("rekor search error: %s", "no matching rekor entries")
	}

	logEntry := resp.Payload[0]
	var rekorEntry models.LogEntryAnon
	for uuid, e := range logEntry {
		if _, err := verifyTlogEntry(context.Background(), e, true,
			trustedRoot); err != nil {
			return nil, fmt.Errorf("error verifying tlog entry: %w", err)
		}
		rekorEntry = e
		url := fmt.Sprintf("%v/%v/%v", defaultRekorAddr, "api/v1/log/entries", uuid)
		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at URL: %s\n", *e.LogIndex, url)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(certPem)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("error unmarshaling certificate from pem")
	}

	env, err := EnvelopeFromBytes(provenance)
	if err != nil {
		return nil, err
	}

	proposedSignedAtt := &SignedAttestation{
		SigningCert: certs[0],
		Envelope:    env,
		RekorEntry:  &rekorEntry,
	}

	if err := verifySignedAttestation(proposedSignedAtt, trustedRoot); err != nil {
		return nil, err
	}

	return proposedSignedAtt, nil
}

// EnvelopeFromBytes reads a DSSE envelope from the given payload.
func EnvelopeFromBytes(payload []byte) (env *dsselib.Envelope, err error) {
	env = &dsselib.Envelope{}
	err = json.Unmarshal(payload, env)
	return
}

func intotoEntry(certPem, provenance []byte) (models.ProposedEntry, error) {
	if len(certPem) == 0 {
		return nil, fmt.Errorf("no signing certificate found in intoto envelope")
	}
	var pubKeyBytes [][]byte
	pubKeyBytes = append(pubKeyBytes, certPem)

	return types.NewProposedEntry(context.Background(), intoto.KIND, intoto_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  provenance,
		PublicKeyBytes: pubKeyBytes,
	})
}

func dsseEntry(certPem, provenance []byte) (models.ProposedEntry, error) {
	if len(certPem) == 0 {
		return nil, fmt.Errorf("no signing certificate found in intoto envelope")
	}

	var pubKeyBytes [][]byte
	pubKeyBytes = append(pubKeyBytes, certPem)

	return types.NewProposedEntry(context.Background(), dsse_rekor.KIND, dsse_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  provenance,
		PublicKeyBytes: pubKeyBytes,
	})
}

// VerifyProvenanceBundle verifies the DSSE envelope using the offline Rekor bundle and
// returns the verified DSSE envelope containing the provenance
// and the signing certificate given the provenance.
func verifyProvenanceBundle(ctx context.Context, bundleBytes []byte,
	trustedRoot *sigstoreRoot.LiveTrustedRoot) (
	*SignedAttestation, error,
) {
	proposedSignedAtt, err := verifyBundleAndEntryFromBytes(ctx, bundleBytes, trustedRoot, true)
	if err != nil {
		return nil, err
	}
	if err := verifySignedAttestation(proposedSignedAtt, trustedRoot); err != nil {
		return nil, err
	}

	return proposedSignedAtt, nil
}

// verifyAttestationSignature validates the signature on the attestation
// given a certificate and a validated signature time from a verified
// Rekor entry.
// The certificate is verified up to Fulcio, the signature is validated
// using the certificate, and the signature generation time is checked
// to be within the certificate validity period.
func verifySignedAttestation(signedAtt *SignedAttestation, trustedRoot *sigstoreRoot.LiveTrustedRoot) error {
	cert := signedAtt.SigningCert
	attBytes, err := cjson.MarshalCanonical(signedAtt.Envelope)
	if err != nil {
		return err
	}
	signatureTimestamp := time.Unix(*signedAtt.RekorEntry.IntegratedTime, 0)

	// Verify the certificate chain, and that the certificate was valid at the time of signing.
	if err := sigstoreVerify.VerifyLeafCertificate(signatureTimestamp, cert, trustedRoot); err != nil {
		return fmt.Errorf("invalid cert: %s", err)
	}

	// Verify the Signed Certificate Timestamps (SCTs).
	if err := sigstoreVerify.VerifySignedCertificateTimestamp(cert, 1, trustedRoot); err != nil {
		return fmt.Errorf("invalid cert: %s", err)
	}

	// Verify the certificate identity information.
	summary, err := sigstoreFulcioCertificate.SummarizeCertificate(cert)
	if err != nil {
		return fmt.Errorf("invalid cert: %s", err)
	}
	certID, err := sigstoreVerify.NewShortCertificateIdentity(certOidcIssuer, "", "", certSubjectRegexp)
	if err != nil {
		return fmt.Errorf("invalid cert: %s", err)
	}
	if err := certID.Verify(summary); err != nil {
		return fmt.Errorf("invalid cert: %s", err)
	}

	// Verify signature using validated certificate.
	verifier, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	if err != nil {
		return err
	}
	verifier = dsseverifier.WrapVerifier(verifier)
	if err := verifier.VerifySignature(bytes.NewReader(attBytes), bytes.NewReader(attBytes)); err != nil {
		return fmt.Errorf("invalid signatures: %s", err)
	}
	return nil
}

// verifyBundleAndEntryFromBytes validates the rekor entry inn the bundle
// and that the entry (cert, signatures) matches the data in the bundle.
func verifyBundleAndEntryFromBytes(ctx context.Context, bundleBytes []byte,
	trustedRoot *sigstoreRoot.LiveTrustedRoot, requireCert bool,
) (*SignedAttestation, error) {
	// Extract the SigningCert, Envelope, and RekorEntry from the bundle.
	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}

	return verifyBundleAndEntry(ctx, &bundle,
		trustedRoot, requireCert)
}

// verifyBundleAndEntry validates the rekor entry inn the bundle
// and that the entry (cert, signatures) matches the data in the bundle.
func verifyBundleAndEntry(ctx context.Context, bundle *protobundle.Bundle,
	trustedRoot *sigstoreRoot.LiveTrustedRoot, requireCert bool,
) (*SignedAttestation, error) {
	// We only expect one TLOG entry. If this changes in the future, we must iterate
	// for a matching one.
	if bundle.GetVerificationMaterial() == nil ||
		len(bundle.GetVerificationMaterial().GetTlogEntries()) == 0 {
		return nil, fmt.Errorf("bundle missing offline tlog verification material %d", len(bundle.GetVerificationMaterial().GetTlogEntries()))
	}

	// Verify tlog entry.
	tlogEntry := bundle.GetVerificationMaterial().GetTlogEntries()[0]
	rekorEntry, err := verifyRekorEntryFromBundle(ctx, tlogEntry, trustedRoot)
	if err != nil {
		return nil, err
	}

	// Extract the PublicKey
	publicKey := bundle.GetVerificationMaterial().GetPublicKey()

	// Extract DSSE envelope.
	env, err := getEnvelopeFromBundle(bundle)
	if err != nil {
		return nil, err
	}

	// Match tlog entry signature with the envelope.
	if err := matchRekorEntryWithEnvelope(tlogEntry, env); err != nil {
		return nil, fmt.Errorf("matching bundle entry with content: %w", err)
	}

	// Get certificate from bundle.
	var cert *x509.Certificate
	if requireCert {
		cert, err = getLeafCertFromBundle(bundle)
		if err != nil {
			return nil, err
		}
	}

	return &SignedAttestation{
		SigningCert: cert,
		PublicKey:   publicKey,
		Envelope:    env,
		RekorEntry:  rekorEntry,
	}, nil
}

// getLeafCertFromBundle extracts the signing cert from the Sigstore bundle.
func getLeafCertFromBundle(bundle *protobundle.Bundle) (*x509.Certificate, error) {
	// Originally, there could be multiple certificates, accessed by `.GetX509CertificateChain().GetCertificates()`.
	// As of v0.3 of the protos, only a single certificate is in the Bundle's VerificationMaterial,
	// and it's access by the auto-generated `GetCertificate()`
	// We keep both methods for backwards compatibility with older bundles.
	// See: https://github.com/sigstore/protobuf-specs/pull/191.

	// First try the newer method.
	if bundleCert := bundle.GetVerificationMaterial().GetCertificate(); bundleCert != nil {
		certBytes := bundleCert.GetRawBytes()
		return x509.ParseCertificate(certBytes)
	}

	// Otherwise, try the original method.
	certChain := bundle.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if len(certChain) == 0 {
		return nil, fmt.Errorf("missing cert bundle")
	}
	// The first certificate is the leaf cert: see
	// https://github.com/sigstore/protobuf-specs/blob/16541696de137c6281d66d075a4924d9bbd181ff/protos/sigstore_common.proto#L170
	certBytes := certChain[0].GetRawBytes()
	return x509.ParseCertificate(certBytes)
}

// getEnvelopeFromBundle extracts the DSSE envelope from the Sigstore bundle.
func getEnvelopeFromBundle(bundle *protobundle.Bundle) (*dsselib.Envelope, error) {
	dsseEnvelope := bundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, fmt.Errorf("failed to get DSSE Envelope")
	}
	env := &dsselib.Envelope{
		PayloadType: dsseEnvelope.GetPayloadType(),
		Payload:     base64.StdEncoding.EncodeToString(dsseEnvelope.GetPayload()),
	}
	for _, sig := range dsseEnvelope.GetSignatures() {
		env.Signatures = append(env.Signatures, dsselib.Signature{
			KeyID: sig.GetKeyid(),
			Sig:   base64.StdEncoding.EncodeToString(sig.GetSig()),
		})
	}
	return env, nil
}

// matchRekorEntryWithEnvelope ensures that the log entry references the given
// DSSE envelope. It MUST verify that the signatures match to ensure that the
// tlog timestamp attests to the signature creation time.
func matchRekorEntryWithEnvelope(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	if len(env.Signatures) == 0 {
		return fmt.Errorf("no signatures")
	}

	kindVersion := tlogEntry.GetKindVersion()

	if kindVersion.Kind == "intoto" && kindVersion.Version == "0.0.2" {
		return matchRekorEntryWithEnvelopeIntotov002(tlogEntry, env)
	}

	if kindVersion.Kind == "dsse" && kindVersion.Version == "0.0.1" {
		return matchRekorEntryWithEnvelopeDSSEv001(tlogEntry, env)
	}

	return fmt.Errorf("unexpected entry type: wanted either intoto v0.0.2 or dsse v0.0.1, got: %s %s", kindVersion.Kind, kindVersion.Version)
}

// matchRekorEntryWithEnvelopeDSSEv001 handles matchRekorEntryWithEnvelope for the intoto v0.0.1 type version.
func matchRekorEntryWithEnvelopeIntotov002(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	canonicalBody := tlogEntry.GetCanonicalizedBody()
	var toto models.Intoto
	var intotoObj models.IntotoV002Schema
	if err := json.Unmarshal(canonicalBody, &toto); err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}
	specMarshal, err := json.Marshal(toto.Spec)
	if err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}
	if err := json.Unmarshal(specMarshal, &intotoObj); err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}

	if len(env.Signatures) != len(intotoObj.Content.Envelope.Signatures) {
		return fmt.Errorf("unequal signatures: wanted %d, got %d",
			len(env.Signatures),
			len(intotoObj.Content.Envelope.Signatures))
	}

	// TODO(#487): verify the certs match.
	for _, sig := range env.Signatures {
		// The signature in the canonical body is double base64-encoded.
		encodedEnvSig := base64.StdEncoding.EncodeToString(
			[]byte(sig.Sig))
		if !slices.ContainsFunc(
			intotoObj.Content.Envelope.Signatures,
			func(canonicalSig *models.IntotoV002SchemaContentEnvelopeSignaturesItems0) bool {
				return canonicalSig.Sig.String() == encodedEnvSig
			},
		) {
			return fmt.Errorf("mismatch signature")
		}
	}

	return nil
}

// matchRekorEntryWithEnvelopeDSSEv001 handles matchRekorEntryWithEnvelope for the dsse v0.0.1 type version.
func matchRekorEntryWithEnvelopeDSSEv001(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	canonicalBody := tlogEntry.GetCanonicalizedBody()
	var dsseObj models.DSSE
	if err := json.Unmarshal(canonicalBody, &dsseObj); err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}
	var dsseSchemaObj models.DSSEV001Schema

	specMarshal, err := json.Marshal(dsseObj.Spec)
	if err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}
	if err := json.Unmarshal(specMarshal, &dsseSchemaObj); err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}

	if len(env.Signatures) != len(dsseSchemaObj.Signatures) {
		return fmt.Errorf("unequal signatures: wanted %d, got %d",
			len(env.Signatures),
			len(dsseSchemaObj.Signatures))
	}
	// TODO(#487): verify the certs match.
	for _, sig := range env.Signatures {
		if !slices.ContainsFunc(
			dsseSchemaObj.Signatures,
			func(canonicalSig *models.DSSEV001SchemaSignaturesItems0) bool {
				return *canonicalSig.Signature == sig.Sig
			},
		) {
			return fmt.Errorf("mismatch signature")
		}
	}
	return nil
}

// verifyRekorEntryFromBundle extracts and verifies the Rekor entry from the Sigstore
// bundle verification material, validating the SignedEntryTimestamp.
func verifyRekorEntryFromBundle(ctx context.Context, tlogEntry *v1.TransparencyLogEntry,
	trustedRoot *sigstoreRoot.LiveTrustedRoot) (
	*models.LogEntryAnon, error,
) {
	canonicalBody := tlogEntry.GetCanonicalizedBody()
	logID := hex.EncodeToString(tlogEntry.GetLogId().GetKeyId())
	rekorEntry := &models.LogEntryAnon{
		Body:           canonicalBody,
		IntegratedTime: &tlogEntry.IntegratedTime,
		LogIndex:       &tlogEntry.LogIndex,
		LogID:          &logID,
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: tlogEntry.GetInclusionPromise().GetSignedEntryTimestamp(),
		},
	}

	// Verify tlog entry.
	if _, err := verifyTlogEntry(ctx, *rekorEntry, false,
		trustedRoot); err != nil {
		return nil, err
	}

	return rekorEntry, nil
}

// verifyTlogEntry verifies a Rekor entry content against a trusted Rekor key.
// Verification includes verifying the SignedEntryTimestamp and, if verifyInclusion
// is true, the inclusion proof along with the signed tree head.
func verifyTlogEntry(ctx context.Context, e models.LogEntryAnon,
	verifyInclusion bool, trustedRoot *sigstoreRoot.LiveTrustedRoot) (
	*models.LogEntryAnon, error,
) {
	// get the public key from sigstore-go
	rekorLogsMap := trustedRoot.RekorLogs()
	keyID := *e.LogID
	rekorLog, ok := rekorLogsMap[keyID]
	if !ok {
		return nil, fmt.Errorf("%s: %s", "error retrieving Rekor public keys", "Rekor log ID not found in trusted root")
	}
	pubKey, ok := rekorLog.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: %s", "error retrieving Rekor public keys", "rekor public key is not an ECDSA key")
	}

	// Verify the root hash against the current Signed Entry Tree Head
	verifier, err := signature.LoadECDSAVerifier(pubKey,
		crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", "error retrieving Rekor public keys", err)
	}

	if verifyInclusion {
		// This function verifies the inclusion proof, the signature on the root hash of the
		// inclusion proof, and the SignedEntryTimestamp.
		err = rverify.VerifyLogEntry(ctx, &e, verifier)
	} else {
		// This function verifies the SignedEntryTimestamp
		err = rverify.VerifySignedEntryTimestamp(ctx, &e, verifier)
	}

	if err != nil {
		return nil, fmt.Errorf("%s: %s", "invalid Rekor entry", err)
	}

	return &e, nil
}

// Type returns the type of the verifier
func (d *sigstoreVerifier) Type() verifier.VerifierType {
	return "sigstore"
}

func verifySignature(k crypto.PublicKey, payload []byte) error {
	vfr, err := signature.LoadVerifier(k, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("could not load verifier: %w", err)
	}

	sigVfr := sig_dsse.WrapVerifier(vfr)

	if err := sigVfr.VerifySignature(bytes.NewReader(payload), nil); err != nil {
		return err
	}
	return nil
}

func parseDSSE(b []byte) (*dsse_ssl.Envelope, error) {
	envelope := dsse_ssl.Envelope{}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}
