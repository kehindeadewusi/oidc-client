package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const (
	clientId     = "client1"
	clientSecret = "client1hashsecret"
	issuer       = "http://localhost:8080"
	callbackURL  = "http://localhost:8081"
	callbackPKCE = "http://localhost:8081/pkce"
)

var (
	tokenEndpoint    = fmt.Sprintf("%s/token", issuer)
	userInfoEndpoint = fmt.Sprintf("%s/userinfo.profile", issuer)
)

func generateNonce() (string, error) {
	b := make([]byte, 16) // 16 bytes for a 128-bit nonce
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
	r.GET("/start-pkce", startPkce)

	r.GET("/", authCode)
	r.GET("/pkce", pkceCode)

	return r
}

func authCode(c *gin.Context) {
	code := c.Query("code")
	fmt.Printf("received code %s\n", code)

	printTokens(code)
}

func b64Encode() string {
	data := fmt.Sprintf("%s:%s", clientId, clientSecret)
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func printTokens(code string) {
	// set the url and form-encoded data for the POST to the access token endpoint
	data := fmt.Sprintf(
		"grant_type=authorization_code&client_id=%s"+
			"&code=%s"+
			"&redirect_uri=%s",
		clientId, code, callbackURL)
	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", tokenEndpoint, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", b64Encode()))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("snap: HTTP error: %s", err)
	}

	// process the response
	defer res.Body.Close()
	var responseData map[string]interface{}
	body, _ := io.ReadAll(res.Body)

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		fmt.Printf("snap: JSON error: %s", err)
	}

	// retrieve the access token out of the map, and return to caller
	accessToken := responseData["access_token"].(string)
	fmt.Println(accessToken)

	token := &oauth2.Token{AccessToken: accessToken, TokenType: "Bearer"}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		fmt.Println(err)
	}
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(userInfo)

}

func printTokens2(code string) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		fmt.Println(err)
	}
	var verifier = provider.Verifier(&oidc.Config{ClientID: clientId})

	config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  callbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes: []string{
			oidc.ScopeOpenID,
			// oidc.ScopeOfflineAccess,
			// "profile",
			// "email",
		},
	}

	token, err := config.Exchange(ctx, code)
	if err != nil {
		fmt.Println("failed to exchange auth code for token: %w", err)
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		fmt.Println("Unable to get ID token")
	} else {
		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(idToken)
		}
	}

	// Extract custom claims
	// var claims struct {
	// 	Email    string `json:"email"`
	// 	Verified bool   `json:"email_verified"`
	// }
	// if err := idToken.Claims(&claims); err != nil {
	// 	// handle error
	// }

	fmt.Printf("Access Token: %s\n", token.AccessToken)
	fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
	fmt.Printf("Expiry: %s\n", token.Expiry)
	fmt.Printf("ID Token: %s\n", rawIDToken)

	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(userInfo)
}

func main() {
	r := setupRouter()
	// Listen and Server in 0.0.0.0:8081
	r.Run(":8081")
}
