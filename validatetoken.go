package introspectionPlugin

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var rsakeys map[string]*rsa.PublicKey

type Post struct {
	Id     int    `json:"id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	UserId int    `json:"userId"`
}

type Config struct {
	IntrospectionUrl     string
	Id       string
	Secret        string
	LogLevel      string
	LogHeaders    []string
}

type Values map[string][]string

type Response map[string]interface{}

type AzureJwtPlugin struct {
	next   http.Handler
	config *Config
}

var (
	LoggerINFO  = log.New(io.Discard, "INFO: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerDEBUG = log.New(io.Discard, "DEBUG: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerWARN  = log.New(io.Discard, "WARN: azure-jwt-token-validator: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func CreateConfig() *Config {
	return &Config{}
}

// New created a new HeaderMatch plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	LoggerWARN.SetOutput(os.Stdout)

	switch config.LogLevel {
	case "INFO":
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	}

	plugin := &AzureJwtPlugin{
		next:   next,
		config: config,
	}

	return plugin, nil
}

func (azureJwt *AzureJwtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	
	tokenValid := false
	errMsg := ""

	posturl := azureJwt.config.IntrospectionUrl

	reqToken := req.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")

	if len(splitToken) != 2 {
		LogHttp(LoggerWARN, "Recieved a request without a valid token.", azureJwt.config.LogHeaders, http.StatusForbidden, req)
		http.Error(rw, "Please provide a valid token.", http.StatusForbidden)
		return
	}
	reqToken = splitToken[1]

	// JSON body
	bodyData := url.Values{}
	bodyData.Set("token", string(reqToken))
	encodedData := bodyData.Encode()

	// Create a HTTP post request
	r, err := http.NewRequest("POST", posturl, strings.NewReader(encodedData))
	if err != nil {

		panic(err)
	}
	var basic = "Basic "
	var data = azureJwt.config.Id + ":" + azureJwt.config.Secret

	sEnc := base64.StdEncoding.EncodeToString([]byte(data))

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(bodyData.Encode())))
	r.Header.Add("Accept", "*/*")
	r.Header.Add("Connection", "keep-alive")
	r.Header.Add("Authorization", basic + sEnc)

	client := &http.Client{}
	res, err := client.Do(r)
	if err != nil {
		errMsg = "Error encountered while making request."
		LogHttp(LoggerWARN, err.Error(), azureJwt.config.LogHeaders, http.StatusForbidden, req)
		panic(err)
	}

	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		LogHttp(LoggerWARN, err.Error(), azureJwt.config.LogHeaders, http.StatusForbidden, req)
	}
	
	target := Response{}

	s := string(b)
	json.Unmarshal([]byte(s), &target)
	
	if(target["active"].(bool)) { 
		tokenValid = true
	} else {
		tokenValid = false
	}

	if tokenValid {
		LogHttp(LoggerWARN, "Token is valid!", azureJwt.config.LogHeaders, http.StatusForbidden, req)
		azureJwt.next.ServeHTTP(rw, req)
	} else {
		LogHttp(LoggerWARN, "The token you provided is not valid. Please provide a valid token. End.", azureJwt.config.LogHeaders, http.StatusForbidden, req)
		http.Error(rw, "The token you provided is not valid. Please provide a valid token. End.", http.StatusForbidden)
	}
}

func verifyAndSetPublicKey(publicKey string) error {
	rsakeys = make(map[string]*rsa.PublicKey)

	if strings.TrimSpace(publicKey) != "" {
		pubPem, _ := pem.Decode([]byte(publicKey))
		if pubPem == nil {
			return fmt.Errorf("public key could not be decoded")
		}
		if pubPem.Type != "RSA PUBLIC KEY" {
			return fmt.Errorf("public key format invalid")
		}

		parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to parse RSA public key")
		}

		if pubKey, ok := parsedKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("unable to convert RSA public key")
		} else {
			rsakeys["config_rsa"] = pubKey
		}
	}

	return nil
}

func (azureJwt *AzureJwtPlugin) ExtractToken(request *http.Request) (*AzureJwt, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		fmt.Println("No authorization header present")
		return nil, errors.New("no authorization header")
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		fmt.Println("not bearer auth scheme")
		return nil, errors.New("not bearer auth scheme")
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		fmt.Println("invalid token format")
		return nil, errors.New("invalid token format")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("Header: %+v", err)
		return nil, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("Payload: %+v", err)
		return nil, errors.New("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Printf("Signature: %+v", err)
		return nil, errors.New("invalid token")
	}
	jwtToken := AzureJwt{
		RawToken:   []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature:  signature,
		RawPayload: payload,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		fmt.Printf("JSON HEADER: %+v", err)
		return nil, errors.New("invalid token")
	}

	return &jwtToken, nil
}

func (claims *Claims) isValidForRole(configRole string) bool {
	for _, parsedRole := range claims.Roles {
		if parsedRole == configRole {
			LoggerDEBUG.Println("Match:", parsedRole, configRole)
			return true
		} else {
			LoggerDEBUG.Println("No match:", parsedRole, configRole)
		}
	}

	return false
}

func LogHttp(logger *log.Logger, message string, headers []string, statusCode int, request *http.Request) {
	var logPayload = make(map[string]string)

	for _, header := range headers {
		logPayload[header] = request.Header.Get(header)
	}

	logPayload["StatusCode"] = strconv.Itoa(statusCode)
	logPayload["Url"] = request.URL.String()
	logPayload["Method"] = request.Method
	logPayload["Error"] = message

	jsonStr, err := json.Marshal(logPayload)

	if err != nil {
		logger.Printf("Error marshaling log payload to JSON: %v\n", err)
		return
	}

	logger.Println(string(jsonStr))
}
