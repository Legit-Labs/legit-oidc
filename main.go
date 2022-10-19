package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/legit-labs/legit-remote-provenance-server/pkg/legit_remote_provenance_server"
	"github.com/legit-labs/legit-remote-provenance/pkg/legit_remote_provenance"
)

func jwtPost(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		fmt.Printf("not a POST request: %v\n", req.Method)
		http.Error(w, "expecting a POST", http.StatusMethodNotAllowed)
		return
	}

	verifyJwt := os.Getenv("bypass_jwt") != "1"
	jwtB64 := req.Header.Get("jwt")
	verifier := legit_remote_provenance_server.NewJwtVerifier(verifyJwt)
	if err := verifier.Verify(jwtB64); err != nil {
		if verifyJwt {
			log.Panicf("failed to verify jwt token: %v", err)
		} else {
			log.Panicf("continue although JWT verification failed because: %v", err)
		}
	}

	var payload legit_remote_provenance.RemoteAttestationData
	err := json.NewDecoder(req.Body).Decode(&payload)
	if err != nil {
		fmt.Printf("missing attestation payload\n")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pg := legit_remote_provenance_server.NewProvenanceGenerator(context.Background(), privateKeyPath)
	signedProv, err := pg.GenerateSignedProvenance(payload)
	if err != nil {
		log.Fatalf("failed to generate provenance: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(signedProv)
	if err != nil {
		fmt.Printf("write error: %v\n", err)
		http.Error(w, "failed to write attestation", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Successfully generated and replied a signed provenance.")
}

func runServer() {
	http.HandleFunc("/", jwtPost)
	fmt.Printf("running server...\n")
	err := http.ListenAndServe(":10000", nil)
	if err != nil {
		fmt.Printf("server error: %v\n", err)
	}
	fmt.Printf("goodbye!\n")
}

var (
	privateKeyPath string
)

func main() {
	flag.StringVar(&privateKeyPath, "private-key", "/tmp/cosign.key", "The path to the private key")
	flag.Parse()

	if privateKeyPath == "" {
		log.Panicf("missing private key path")
	}

	fmt.Printf("start server\n")
	runServer()
}
