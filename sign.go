package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func sign(ctx context.Context, key string, payload []byte) ([]byte, error) {
	sv, err := signature.SignerVerifierFromKeyRef(ctx, key, nil)
	if err != nil {
		return nil, err
	}

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	fmt.Printf("Hello world!\n")

	return signedPayload, nil
}

func attestationToEnvelope(attestation []byte) (*dsselib.Envelope, error) {
	var env dsselib.Envelope

	if err := json.Unmarshal(attestation, &env); err != nil {
		return nil, err
	}

	return &env, nil
}

func verifiedPayload(ctx context.Context, key string, attestation []byte) ([]byte, error) {
	envelope, err := attestationToEnvelope(attestation)
	if err != nil {
		return nil, err
	}

	sv, err := signature.PublicKeyFromKeyRef(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("Failed to load pub key: %v\n", err)
	}

	dssev, err := dsselib.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: sv})
	if err != nil {
		return nil, err
	}
	_, err = dssev.Verify(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed verify: %v\n", err)
	}

	return []byte(envelope.Payload), nil
}
