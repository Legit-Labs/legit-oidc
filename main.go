package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func getJwks() ([]byte, error) {
	resp, err := http.Get("https://token.actions.githubusercontent.com/.well-known/jwks")
	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	return body, nil
}

func parseToken(jwtB64 string, jkwsJSON []byte) (*jwt.Token, error) {
	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.NewJSON(jkwsJSON)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}

	// Parse the JWT.
	token, err := jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	return token, nil
}

func verify(jwtB64 string) (*jwt.Token, error) {
	jkws, err := getJwks()
	if err != nil {
		return nil, fmt.Errorf("failed to get jkws: %v", err)
	}

	token, err := parseToken(jwtB64, jkws)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	// Check if the token is valid.
	if !token.Valid {
		return nil, fmt.Errorf("The token is not valid.")
	}

	log.Println("The token is valid.")
	return token, nil
}

func verifyClaims(token *jwt.Token) error {
	fmt.Printf("get claims...\n")
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("failed to parse claims")
	}

	fmt.Printf("check exists...\n")
	_jobRef, exist := claims["job_workflow_ref"]
	if !exist {
		return fmt.Errorf("missing job workflow ref")
	}

	fmt.Printf("get jobref...\n")
	jobRef, ok := _jobRef.(string)
	if !ok {
		return fmt.Errorf("failed to parse job ref")
	}

	fmt.Printf("check jobref...\n")
	if !strings.HasPrefix(strings.ToLower(jobRef), "legit-labs") { // TODO full name
		return fmt.Errorf("bad workflow ref")
	}

	return nil
}

func jwtPost(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		fmt.Printf("not a POST request: %v\n", req.Method)
		http.Error(w, "expecting a POST", http.StatusMethodNotAllowed)
		return
	}

	jwt := req.Header.Get("authorization")
	if jwt == "" {
		fmt.Printf("no auth header\n")
		http.Error(w, "no auth header", http.StatusBadRequest)
		return
	}

	fmt.Printf("check payload\n")
	var payload interface{}
	err := json.NewDecoder(req.Body).Decode(&payload)
	if err != nil {
		fmt.Printf("missing attestation payload\n")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("fail json to bytes\n")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Printf("verify token\n")
	token, err := verify(jwt)
	if err != nil {
		fmt.Printf("jwt verification failed: %v\n", err)
		http.Error(w, "jwt verification failed", http.StatusBadRequest)
		return
	}

	fmt.Printf("verify claims\n")
	if err := verifyClaims(token); err != nil {
		fmt.Printf("jwt claims failed: %v\n", err)
		http.Error(w, "jwt claims failed", http.StatusBadRequest)
		return
	}

	attestation, err := sign(context.Background(), "/tmp/cosign.key", payloadBytes)
	if err != nil {
		fmt.Printf("sign error: %v\n", err)
		http.Error(w, "failed to sign attestation", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attestation)
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

func main() {
	fmt.Printf("Hello world!\n")
	runServer()
}
