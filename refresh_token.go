package main

import (
"encoding/json"
"fmt"
"io"
"log"
"net/http"
"net/url"
"os"
"strings"
)

// TokenResponse represents the structure of tokens in tokens.txt
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
	ClientType       string `json:"client_type"`
}

func main() {
	// Read current tokens
	tokenFile, err := os.Open("tokens.txt")
	if err != nil {
		log.Fatalf("failed to open tokens.txt: %v", err)
	}
	defer tokenFile.Close()

	tokenData, err := io.ReadAll(tokenFile)
	if err != nil {
		log.Fatalf("failed to read tokens.txt: %v", err)
	}

	var tokens TokenResponse
	if err := json.Unmarshal(tokenData, &tokens); err != nil {
		log.Fatalf("failed to parse tokens: %v", err)
	}

	// Prepare refresh request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokens.RefreshToken)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://auth.mangadx.org/realms/mangadx/protocol/openid-connect/token", 
strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatalf("failed to create refresh request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("failed to make refresh request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read refresh response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var newTokens TokenResponse
	if err := json.Unmarshal(body, &newTokens); err != nil {
		log.Fatalf("failed to parse refresh response: %v", err)
	}

	// Save the new tokens back to file
	newTokenData, err := json.Marshal(newTokens)
	if err != nil {
		log.Fatalf("failed to marshal new tokens: %v", err)
	}

	if err := os.WriteFile("tokens.txt", newTokenData, 0644); err != nil {
		log.Fatalf("failed to save new tokens: %v", err)
	}

	fmt.Println("🔄 Access token refreshed successfully!")
}
