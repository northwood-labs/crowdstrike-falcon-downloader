// Copyright 2024, Northwood Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crowdstrike

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/schollz/progressbar/v3"
)

// ExchangeKeys exchanges OAuth tokens for API keys with the CrowdStrike API.
func ExchangeKeys(verbose bool) (string, error) {
	requestBody := fmt.Sprintf(
		"client_id=%s&client_secret=%s",
		os.Getenv("CROWDSTRIKE_CLIENT_ID"),
		os.Getenv("CROWDSTRIKE_CLIENT_SECRET"),
	)

	request, err := http.NewRequest(
		"POST",
		"https://api.crowdstrike.com/oauth2/token",
		bytes.NewBuffer([]byte(requestBody)),
	)
	if err != nil {
		return "", fmt.Errorf("could not construct the HTTP request: %w", err)
	}

	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("could not perform the HTTP request: %w", err)
	}

	defer response.Body.Close()

	oAuth := &OAuthResp{}
	derr := json.NewDecoder(response.Body).Decode(oAuth)
	if derr != nil {
		return "", fmt.Errorf("could not decode the API response as JSON: %w", err)
	}

	if response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected HTTP status code: %d", response.StatusCode)
	}

	return oAuth.AccessToken, nil
}

func ListInstallers(token string, verbose bool) ([]ListResources, error) {
	emptyResponse := []ListResources{}

	request, err := http.NewRequest(
		"GET",
		"https://api.crowdstrike.com/sensors/combined/installers/v1",
		nil,
	)
	if err != nil {
		return emptyResponse, fmt.Errorf("could not construct the HTTP request: %w", err)
	}

	request.Header.Add("Authorization", "Bearer "+token)
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return emptyResponse, fmt.Errorf("could not perform the HTTP request: %w", err)
	}

	defer response.Body.Close()

	listResp := &ListResp{}
	derr := json.NewDecoder(response.Body).Decode(listResp)
	if derr != nil {
		return emptyResponse, fmt.Errorf("could not decode the API response as JSON: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return emptyResponse, fmt.Errorf("unexpected HTTP status code: %d", response.StatusCode)
	}

	return listResp.Resources, nil
}

func DownloadInstaller(token, sha256, filename string, contentLength int64) error {
	url := "https://api.crowdstrike.com/sensors/entities/download-installer/v1?id=" + sha256

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("could not create the request to download: %w", err)
	}

	request.Header.Add("Authorization", "Bearer "+token)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("could not perform download: %w", err)
	}

	defer response.Body.Close()

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("could not write new file to disk: %w", err)
	}

	defer f.Close()

	bar := progressbar.DefaultBytes(contentLength, filename)

	_, err = io.Copy(io.MultiWriter(f, bar), response.Body)
	if err != nil {
		return fmt.Errorf("could not perform download into file: %w", err)
	}

	return nil
}
