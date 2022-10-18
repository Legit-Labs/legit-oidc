package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/legit-labs/legit-attestation/pkg/legit_remote_attest"
)

func CmdExec(args ...string) (string, error) {

	baseCmd := args[0]
	cmdArgs := args[1:]

	cmd := exec.Command(baseCmd, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

const OUT_PATH = "/tmp/result.intoto.jsnol"

func sign(ctx context.Context, key string, payload legit_remote_attest.RemoteAttestationData) ([]byte, error) {
	fmt.Printf("got: %#v\n", payload)

	if err := payload.ApplyToEnv(); err != nil {
		return nil, fmt.Errorf("failed to apply env: %v", err)
	}

	res, err := CmdExec("./generator", "attest", "--subjects", payload.SubjectsBase64, "--predicate", OUT_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}
	log.Printf("attest output: %v\n", res)

	output, err := os.ReadFile(OUT_PATH)
	if err != nil {
		return nil, fmt.Errorf("failed to read output: %v", err)
	}

	return output, nil
}
