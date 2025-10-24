package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	clientId     = "client1"
	clientSecret = "whatever password"
	issuer       = "http://localhost:8080"
	callbackURL  = "http://localhost:8081"
)

var (
	tokenEndpoint = fmt.Sprintf("%s/token", issuer)
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
	r.GET("/start-confidential", startConfidential)

	r.GET("/pkce", pkce)
	r.GET("/confidential", confidential)

	return r
}

func main() {
	r := setupRouter()
	r.Run(":8081")
}
