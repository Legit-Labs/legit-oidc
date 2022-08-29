package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

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

func verify(jwtB64 string) error {
	jkws, err := getJwks()
	if err != nil {
		return fmt.Errorf("failed to get jkws: %v", err)
	}

	token, err := parseToken(jwtB64, jkws)
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	// Check if the token is valid.
	if !token.Valid {
		return fmt.Errorf("The token is not valid.")
	}

	log.Println("The token is valid.")
	return nil
}
func jwtPost(w http.ResponseWriter, req *http.Request) {
	jwt := req.Header.Get("authorization")

	if req.Method != "POST" {
		fmt.Printf("not a POST request: %v\n", req.Method)
		return
	}

	if jwt == "" {
		fmt.Printf("no auth header\n")
		return
	}

	err := verify(jwt)
	if err != nil {
		fmt.Printf("Failed: %v\n", err)
	}
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

	data := struct {
		A int `json:"a"`
	}{15}
	payload, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("payload error: %v\n", err)
	}

	s, err := sign(context.Background(), "/tmp/cosign.key", payload)
	if err != nil {
		fmt.Printf("sign error: %v\n", err)
	}
	fmt.Printf("signed: %v\n", string(s))

	runServer()
}
