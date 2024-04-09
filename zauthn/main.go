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
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type zPrivateKey struct {
	UserID string `json:"userId"`
	KeyID  string `json:"keyId"`
	Key    string `json:"key"`
}

type zToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	ErrorDescription string `json:"error_description"`
}

func getZPrivateKey(path string) *zPrivateKey {
	file, err := os.Open(path)
	if err != nil {
		log.Panic(err)
	}
	bytes, _ := io.ReadAll(file)

	var key zPrivateKey
	err = json.Unmarshal(bytes, &key)
	if err != nil {
		log.Panic(err)
	}
	return &key
}

func issueToken(key zPrivateKey, apiURL string, duration time.Duration) string {

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key.Key))

	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()

	issuedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": key.UserID,
		"sub": key.UserID,
		"aud": apiURL,
		"iat": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(duration)),
	})

	issuedToken.Header = map[string]any{
		"typ": "JWT",
		"alg": "RS256",
		"kid": key.KeyID,
	}

	token, err := issuedToken.SignedString(privateKey)
	if err != nil {
		log.Panicf("Error signing token: %v", err)
	}

	return token
}

func issueZToken(client *http.Client, apiURL string, signedToken string) (string, time.Duration, error) {

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("scope", "openid")
	data.Set("assertion", signedToken)

	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer res.Body.Close()
	reqBody, err := io.ReadAll(res.Body)
	if err != nil {
		log.Panic(err)
	}

	var zToken zToken
	err = json.Unmarshal(reqBody, &zToken)
	if err != nil {
		return "", 0, err
	}
	if zToken.ErrorDescription != "" {
		return "", 0, fmt.Errorf(zToken.ErrorDescription)
	}

	return zToken.AccessToken, time.Duration(zToken.ExpiresIn) * time.Second, nil
}

func main() {

	api_url, exists := os.LookupEnv("ZITADEL_URL")
	if !exists {
		log.Panic("ZITADEL_URL is missing")
	}

	private_key_path := os.Getenv("ZAUTHN_PRIVATE_KEY_FILE")
	token_path := os.Getenv("ZAUTHN_WID_TOKEN_FILE")

	ZAUTHN_TOKEN_REFRESH_LEAD_TIME := os.Getenv("ZAUTHN_TOKEN_REFRESH_LEAD_TIME")

	refresh_before, err := time.ParseDuration(ZAUTHN_TOKEN_REFRESH_LEAD_TIME)
	if err != nil {
		log.Panic(err)
	}

	issue_token_api_url := fmt.Sprintf("%s/oauth/v2/token", api_url)

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	for {
		zPrivateKey := getZPrivateKey(private_key_path)
		token := issueToken(*zPrivateKey, api_url, time.Minute)
		zToken, expires_in, err := issueZToken(&client, issue_token_api_url, token)
		if err != nil {
			log.Printf("error issuing zToken: %v", err)
			time.Sleep(time.Second)
			continue
		}
		err = os.WriteFile(token_path, []byte(zToken), 0644)
		if err != nil {
			log.Panic(err)
		}
		refresh_in := expires_in - refresh_before
		if refresh_in < time.Minute {
			log.Printf("Warning: Token will expire in %s, refresh interval is set to %s", expires_in, refresh_in)
			refresh_in = time.Minute
		} else if refresh_before == 0 {
			log.Printf("Warning: Token will expire in %s. Exiting", expires_in)
			os.Exit(0)
		}
		log.Printf("Refreshing in %s", refresh_in)
		time.Sleep(refresh_in)
	}
}
