package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// Starts the OAuth2 Authorization Code flow.
func startConfidential(c *gin.Context) {
	// construct the authorization URL (with Auth0 as the authorization provider)
	authorizationURL := fmt.Sprintf(
		"%s/authorize?audience=wsthings"+
			"&scope=openid email profile"+
			"&response_type=code"+
			"&client_id=%s"+
			"&client_secret=%s"+
			"&redirect_uri=%s",
		issuer, clientId, clientSecret, url.QueryEscape(callbackURL+"/confidential"))

	// open a browser window to the authorizationURL
	err = open.Start(authorizationURL)
	if err != nil {
		fmt.Printf("snap: can't open browser to URL %s: %s\n", authorizationURL, err)
		os.Exit(1)
	}
}

func confidential(c *gin.Context) {
	code := c.Query("code")
	fmt.Printf("received code %s\n", code)

	accessToken, _ := exchangePost(code)
	userInfoConfidential(accessToken)
	introspectWithPost(accessToken)
}

func exchangePost(code string) (string, string) {
	// set the url and form-encoded data for the POST to the access token endpoint
	data := fmt.Sprintf(
		"grant_type=authorization_code"+
			"&client_id=%s"+
			"&client_secret=%s"+
			"&code=%s"+
			"&redirect_uri=%s",
		clientId, clientSecret, code, url.QueryEscape(callbackURL+"/confidential"))
	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", tokenEndpoint, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
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
	idToken := responseData["id_token"].(string)
	fmt.Println(accessToken)
	fmt.Println(idToken)

	return accessToken, idToken
}

func userInfoConfidential(accessToken string) {
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

func introspectWithPost(token string) {
	introspectionEndpoint := fmt.Sprintf("%s/introspect", issuer)

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	data.Set("token_type_hint", "access_token") // Optional hint

	client := &http.Client{}
	req, err := http.NewRequest("POST", introspectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	fmt.Println("Introspection Response:", result)
	if active, ok := result["active"].(bool); ok && active {
		fmt.Println("Token is active.")
	} else {
		fmt.Println("Token is inactive or invalid.")
	}
}
