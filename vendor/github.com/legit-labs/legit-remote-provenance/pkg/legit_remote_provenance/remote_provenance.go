package legit_remote_provenance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type LegitEndpoint struct {
	Url      string
	ApiToken string
}

type RemoteAttestationData struct {
	Env            map[string]string
	SubjectsBase64 string
}

func getEnv() map[string]string {
	envStrings := os.Environ()
	env := make(map[string]string, len(envStrings))
	for _, kv := range envStrings {
		pair := strings.SplitN(kv, "=", 2)
		key := pair[0]
		value := pair[1]
		env[key] = value
	}
	return env
}

func NewRemoteAttestationData(subjectsBase64 string) RemoteAttestationData {
	return RemoteAttestationData{
		Env:            getEnv(),
		SubjectsBase64: subjectsBase64,
	}
}

func (rd RemoteAttestationData) asPostData() (*bytes.Buffer, error) {
	envBytes, err := json.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling json: %w", err)
	}

	return bytes.NewBuffer(envBytes), nil
}
func (rd RemoteAttestationData) ApplyToEnv() error {
	for k, v := range rd.Env {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}

	return nil
}

func AttestWithToken(subjectsBase64 string, endpoint LegitEndpoint, jwt string) ([]byte, error) {
	postData, err := NewRemoteAttestationData(subjectsBase64).asPostData()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", endpoint.Url, postData)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("jwt", jwt)

	legitApiHeader := MakeBearerHeader(endpoint.ApiToken)
	request.Header.Set(legitApiHeader[0], legitApiHeader[1])

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing response: %v", body)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response from server (%v): %v\n", response.StatusCode, string(body))
	}

	return body, nil
}

func Attest(subjectsBase64 string, endpoint LegitEndpoint) ([]byte, error) {
	token, err := GetJWTToken()
	if err != nil {
		return nil, err
	}

	result, err := AttestWithToken(subjectsBase64, endpoint, token)
	if err != nil {
		return nil, err
	}

	return result, nil
}
