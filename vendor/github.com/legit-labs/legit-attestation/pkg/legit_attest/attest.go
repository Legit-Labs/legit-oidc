package legit_attest

import (
	"bytes"
	"context"

	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func Attest(ctx context.Context, keyRef string, payload []byte) ([]byte, error) {
	sv, err := signature.SignerVerifierFromKeyRef(ctx, keyRef, nil)
	if err != nil {
		return nil, err
	}

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return signedPayload, nil
}
