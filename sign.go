package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/legit-labs/legit-attestation/pkg/legit_remote_attest"
)

func CmdExec(args ...string) error {

	baseCmd := args[0]
	cmdArgs := args[1:]

	cmd := exec.Command(baseCmd, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func sign(ctx context.Context, keyRef string, payload legit_remote_attest.RemoteAttestationData) ([]byte, error) {
	// fmt.Printf("got: %#v\n", payload)

	if err := payload.ApplyToEnv(); err != nil {
		return nil, fmt.Errorf("failed to apply env: %v", err)
	}

	os.Setenv("PRIVATE_KEY_PATH", keyRef)

	err := CmdExec("./generator", "attest", "--subjects", payload.SubjectsBase64, "--signature", "", "--predicate", "")
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}

	output, err := os.ReadFile(OUT_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to read output: %v", err)
	}

	return output, nil
}
