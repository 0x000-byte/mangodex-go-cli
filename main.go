package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	baseURL       = "https://api.mangadex.org"
	tokenFilePath = "tokens.txt"
)

var (
	httpClient      = &http.Client{Timeout: 10 * time.Second}
	errUnauthorized = errors.New("unauthorized")
)

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
	FetchedAt        int64  `json:"fetched_at,omitempty"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type APIResponse[T any] struct {
	Result string `json:"result"`
	Data   T      `json:"data"`
}

func main() {
	// 1) Try loading tokens.txt
	tokens, err := loadTokens(tokenFilePath)
	if err != nil {
		log.Println("No valid tokens on disk, logging in…")
		tokens, err = login()
		if err != nil {
			log.Fatalf("login error: %v", err)
		}
		if err := saveTokens(tokenFilePath, tokens); err != nil {
			log.Printf("warning: could not save tokens: %v", err)
		}
	}

	// 2) Call /user/me, refresh if we get a 401
	user, err := getUserInfo(tokens.AccessToken)
	if err == errUnauthorized {
		log.Println("Access token expired, refreshing…")
		tokens, err = refreshToken(tokens.RefreshToken)
		if err != nil {
			log.Printf("refresh failed: %v", err)
			log.Println("Re‑logging in…")
			tokens, err = login()
			if err != nil {
				log.Fatalf("login after refresh failure error: %v", err)
			}
		}
		if err := saveTokens(tokenFilePath, tokens); err != nil {
			log.Printf("warning: could not save tokens: %v", err)
		}

		user, err = getUserInfo(tokens.AccessToken)
	}
	if err != nil {
		log.Fatalf("failed to get user info: %v", err)
	}

	// 3) Success
	fmt.Printf("✅ Logged in as: %s\n📧 Email: %s\n🆔 User ID: %s\n",
		user.Username, user.Email, user.ID)
}

func loadTokens(path string) (*TokenResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var tr TokenResponse
	if err := json.NewDecoder(f).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

func saveTokens(path string, tr *TokenResponse) error {
	tr.FetchedAt = time.Now().Unix()
	data, err := json.MarshalIndent(tr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func login() (*TokenResponse, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("MangaDex username: ")
	user, _ := reader.ReadString('\n')
	fmt.Print("MangaDex password: ")
	pass, _ := reader.ReadString('\n')

	user = strings.TrimSpace(user)
	pass = strings.TrimSpace(pass)

	payload := map[string]string{
		"username": user,
		"password": pass,
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed (%d): %s", resp.StatusCode, string(b))
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	tr.FetchedAt = time.Now().Unix()
	return &tr, nil
}

func getUserInfo(accessToken string) (*User, error) {
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/user/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var r APIResponse[User]
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return nil, err
		}
		return &r.Data, nil
	case http.StatusUnauthorized:
		return nil, errUnauthorized
	default:
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(b))
	}
}

func refreshToken(refreshToken string) (*TokenResponse, error) {
	payload := map[string]string{"refreshToken": refreshToken}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh failed (%d): %s", resp.StatusCode, string(b))
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	tr.FetchedAt = time.Now().Unix()
	return &tr, nil
}
