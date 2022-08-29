package main

import (
	"bytes"
	"context"
	"fmt"

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
