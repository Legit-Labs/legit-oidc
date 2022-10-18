package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/legit-labs/legit-attestation/pkg/legit_remote_attest"
)

func sign(ctx context.Context, key string, payload legit_remote_attest.RemoteAttestationData) ([]byte, error) {
	fmt.Printf("got: %#v\n", payload)
	res := make(map[string]string)
	res["test"] = "works"
	return json.Marshal(res)
}
