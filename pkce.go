package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/skratchdot/open-golang/open"
)

var CodeVerifier, err = cv.CreateCodeVerifier()

// AuthorizeUser implements the PKCE OAuth2 flow.
func startPkce(c *gin.Context) {
	// initialize the code verifier
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create code_challenge with S256 method
	codeChallenge := CodeVerifier.CodeChallengeS256()

	// construct the authorization URL (with Auth0 as the authorization provider)
	authorizationURL := fmt.Sprintf(
		"%s/authorize?audience=wsthings"+
			"&scope=openid"+
			"&response_type=code&client_id=%s"+
			"&code_challenge=%s"+
			"&code_challenge_method=S256&redirect_uri=%s",
		issuer, clientId, codeChallenge, url.QueryEscape(callbackPKCE))

	// open a browser window to the authorizationURL
	err = open.Start(authorizationURL)
	if err != nil {
		fmt.Printf("snap: can't open browser to URL %s: %s\n", authorizationURL, err)
		os.Exit(1)
	}
}

func pkceCode(c *gin.Context) {
	code := c.Query("code")
	fmt.Printf("received code %s\n", code)

	codeVerifier := CodeVerifier.String()
	token, err := getAccessToken(codeVerifier, code)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(token)
	}
}

func getAccessToken(codeVerifier, authorizationCode string) (string, error) {
	// set the url and form-encoded data for the POST to the access token endpoint
	url := tokenEndpoint
	data := fmt.Sprintf(
		"grant_type=authorization_code&client_id=%s"+
			"&code_verifier=%s"+
			"&code=%s"+
			"&redirect_uri=%s",
		clientId, codeVerifier, authorizationCode, callbackPKCE,
	)
	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("snap: HTTP error: %s", err)
		return "", err
	}

	// process the response
	defer res.Body.Close()
	var responseData map[string]interface{}
	body, _ := io.ReadAll(res.Body)

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		fmt.Printf("snap: JSON error: %s", err)
		return "", err
	}

	// retrieve the access token out of the map, and return to caller
	accessToken := responseData["access_token"].(string)
	return accessToken, nil
}

// To send a token introspection request to an OIDC authorization server
func introspect() {
	introspectionEndpoint := "YOUR_INTROSPECTION_ENDPOINT_URL" // Replace with actual URL
	accessToken := "YOUR_ACCESS_TOKEN"                         // Replace with the token to introspect
	clientID := "YOUR_CLIENT_ID"                               // Optional: if client authentication is needed
	clientSecret := "YOUR_CLIENT_SECRET"                       // Optional: if client authentication is needed

	data := url.Values{}
	data.Set("token", accessToken)
	// data.Set("token_type_hint", "access_token") // Optional hint

	client := &http.Client{}
	req, err := http.NewRequest("POST", introspectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Add client authentication if required
	if clientID != "" && clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
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
