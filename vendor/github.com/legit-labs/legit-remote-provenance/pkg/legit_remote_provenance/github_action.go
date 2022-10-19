package legit_remote_provenance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	// See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#updating-your-actions-for-oidc
	REQ_AUDIENCE = "legit-security-provenance-generator"
	REQ_TOKEN    = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	REQ_URL      = "ACTIONS_ID_TOKEN_REQUEST_URL"
)

func MakeBearerHeader(token string) []string {
	return []string{
		"Authorization",
		"bearer " + token,
	}
}

func getActionsURL() string {
	return os.Getenv(REQ_URL)
}

func getActionsTokenHeader() []string {
	token := os.Getenv(REQ_TOKEN)
	return MakeBearerHeader(token)
}

func GetJWTToken() (string, error) {
	url := getActionsURL()
	request, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte{}))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	token := getActionsTokenHeader()
	request.Header.Set(token[0], token[1])

	q := request.URL.Query()
	q.Add("audience", REQ_AUDIENCE)
	request.URL.RawQuery = q.Encode()

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var result struct {
		Count int    `json:"count"`
		Value string `json:"value"`
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return result.Value, nil
}
