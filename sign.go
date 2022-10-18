package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/legit-labs/legit-attestation/pkg/legit_attest"
	"github.com/legit-labs/legit-attestation/pkg/legit_remote_attest"
)

func CmdExec(args ...string) ([]byte, error) {

	baseCmd := args[0]
	cmdArgs := args[1:]

	cmd := exec.Command(baseCmd, cmdArgs...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	return output, err
}

func sign(ctx context.Context, keyRef string, payload legit_remote_attest.RemoteAttestationData) ([]byte, error) {
	// fmt.Printf("got: %#v\n", payload)

	if err := payload.ApplyToEnv(); err != nil {
		return nil, fmt.Errorf("failed to apply env: %v", err)
	}

	output, err := CmdExec("./generator", "attest", "--subjects", payload.SubjectsBase64, "--signature", "", "--predicate", "")
	if err != nil {
		return nil, fmt.Errorf("failed to generate provenance: %v", err)
	}

	signed, err := legit_attest.Attest(ctx, keyRef, output)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %v", err)
	}

	return signed, nil
}
