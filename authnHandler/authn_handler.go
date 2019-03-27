package authnHandler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type OpenIDConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	ProviderURL  string `yaml:"provider_url"`
	AuthURL      string `yaml:"auth_url"`
	TokenURL     string `yaml:"token_url"`
	UserinfoURL  string `yaml:"userinfo_url"`
	Scopes       string `yaml:"scopes"`
}

type AuthInfo struct {
	Username   string `json:"username,omitempty"`
	ExpiresAt  time.Time
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
}

type AuthNHandler struct {
	handler        http.Handler
	openID         OpenIDConfig
	authCookieName string
	netClient      *http.Client
	SharedSecrets  []string
}

type oauth2StateJWT struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	ReturnURL  string   `json:"return_url,omitempty"`
}

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:expires_in`
	IDToken     string `json:"id_token"`
}

type openidConnectUserInfo struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	Login             string `json:"login,omitempty"`
	Username          string `json:"username,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
}

const cookieNamePrefix = "authn_cookie"
const secondsBetweenCleanup = 60
const cookieExpirationHours = 3
const maxAgeSecondsRedirCookie = 120
const redirCookieName = "oauth2_redir"
const oauth2redirectPath = "/oauth2/redirectendpoint"
const authNCookieExpirationDuration = 8 * 3600 * time.Second

// Generates a valid auth cookie that can be used by clients, should only be used
// by users of the lib in their test functions
func (h *AuthNHandler) GenValidAuthCookie(username string) (*http.Cookie, error) {
	expires := time.Now().Add(time.Hour * cookieExpirationHours)
	return h.genValidAuthCookieExpiration(username, expires, "localhost")
}

func (h *AuthNHandler) genValidAuthCookieExpiration(
	username string, expires time.Time, issuer string) (*http.Cookie, error) {
	key := []byte(h.SharedSecrets[0])
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		//log.Printf("err=%s", err)
		return nil, fmt.Errorf("genValidAuthCookieExpiration: %s", err)
	}
	subject := "state:" + h.authCookieName
	authToken := AuthInfo{
		Issuer: issuer, Subject: subject,
		Audience:   []string{issuer},
		Username:   username,
		Expiration: expires.Unix(),
	}
	// TODO: add IssuedAt and NotBefore?
	authToken.NotBefore = time.Now().Unix()
	//stateToken.IssuedAt = stateToken.NotBefore

	cookieValue, err := jwt.Signed(sig).Claims(authToken).CompactSerialize()
	if err != nil {
		return nil, err
	}

	userCookie := http.Cookie{Name: h.authCookieName, Value: cookieValue, Path: "/", Expires: expires, HttpOnly: true, Secure: true}
	return &userCookie, nil
}

func (h *AuthNHandler) setAndStoreAuthCookie(w http.ResponseWriter, r *http.Request, username string, expires time.Time) error {
	userCookie, err := h.genValidAuthCookieExpiration(username, expires, r.Host)
	if err != nil {
		return err
	}
	http.SetCookie(w, userCookie)
	return nil
}

func (h *AuthNHandler) getRedirURL(r *http.Request) string {
	return "https://" + r.Host + oauth2redirectPath
}

func (h *AuthNHandler) generateAuthCodeURL(state string, r *http.Request) string {
	var buf bytes.Buffer
	buf.WriteString(h.openID.AuthURL)
	redirectURL := h.getRedirURL(r)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {h.openID.ClientID},
		"scope":         {h.openID.Scopes},
		"redirect_uri":  {redirectURL},
	}

	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}
	if strings.Contains(h.openID.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

func (h *AuthNHandler) generateValidStateString(r *http.Request) (string, error) {
	key := []byte(h.SharedSecrets[0])
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		log.Printf("err=%s", err)
		//http.Error(w, "Internal Errorrn "http.StatusInternalServerError)
		return "", err
	}
	issuer := r.Host
	subject := "state:" + redirCookieName
	stateToken := oauth2StateJWT{Issuer: issuer, Subject: subject,
		Audience:  []string{issuer},
		ReturnURL: r.URL.String()}
	stateToken.NotBefore = time.Now().Unix()
	stateToken.IssuedAt = stateToken.NotBefore
	stateToken.Expiration = stateToken.IssuedAt + maxAgeSecondsRedirCookie
	return jwt.Signed(sig).Claims(stateToken).CompactSerialize()
}

// This is where the redirect to the oath2 provider is computed.
func (h *AuthNHandler) oauth2DoRedirectoToProviderHandler(w http.ResponseWriter, r *http.Request) {
	stateString, err := h.generateValidStateString(r)
	if err != nil {
		log.Printf("err=%s", err)
		http.Error(w, "Internal Error ", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, h.generateAuthCodeURL(stateString, r), http.StatusFound)
}

//Next are the functions fo checking the callback
func (h *AuthNHandler) JWTClaims(t *jwt.JSONWebToken, dest ...interface{}) (err error) {
	for _, key := range h.SharedSecrets {
		binkey := []byte(key)
		err = t.Claims(binkey, dest...)
		if err == nil {
			return nil
		}
	}
	if err != nil {
		return err
	}
	err = errors.New("No valid key found")
	return err
}

func getUsernameFromUserinfo(userInfo openidConnectUserInfo) string {
	username := userInfo.Username
	if len(username) < 1 {
		username = userInfo.Login
	}
	if len(username) < 1 {
		username = userInfo.PreferredUsername
	}
	if len(username) < 1 {
		username = userInfo.Email
	}
	return username
}

func (h *AuthNHandler) getBytesFromSuccessfullPost(url string, data url.Values) ([]byte, error) {
	response, err := h.netClient.PostForm(url, data)
	if err != nil {
		log.Printf("err=%s", err)
		return nil, err
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("err=%s", err)

		return nil, err
	}

	if response.StatusCode >= 300 {
		log.Printf(string(responseBody))
		return nil, errors.New("invalid status code")
	}
	return responseBody, nil
}

func (h *AuthNHandler) getVerifyReturnStateJWT(r *http.Request) (oauth2StateJWT, error) {
	inboundJWT := oauth2StateJWT{}
	serializedState := r.URL.Query().Get("state")
	if len(serializedState) < 1 {
		return inboundJWT, errors.New("null inbound state")
	}
	tok, err := jwt.ParseSigned(serializedState)
	if err != nil {
		return inboundJWT, err
	}
	if err := h.JWTClaims(tok, &inboundJWT); err != nil {
		log.Printf("error parsing claims err=%s", err)
		return inboundJWT, err
	}
	// At this point we know the signature is valid, but now we must
	//validate the contents of the jtw token
	issuer := r.Host
	subject := "state:" + redirCookieName
	if inboundJWT.Issuer != issuer || inboundJWT.Subject != subject ||
		inboundJWT.NotBefore > time.Now().Unix() || inboundJWT.Expiration < time.Now().Unix() {
		err = errors.New("invalid JWT values")
		return inboundJWT, err
	}
	return inboundJWT, nil
}

func (h *AuthNHandler) oauth2RedirectPathHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		log.Printf("Bad method on redirect, should only be GET")
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	authCode := r.URL.Query().Get("code")
	if len(authCode) < 1 {
		log.Println("null code")
		http.Error(w, "null code", http.StatusUnauthorized)
		return
	}
	inboundJWT, err := h.getVerifyReturnStateJWT(r)
	if err != nil {
		log.Printf("error processing state err=%s", err)
		http.Error(w, "null or bad inboundState", http.StatusUnauthorized)
		return
	}
	// OK state  is valid.. now we perform the token exchange
	redirectURL := h.getRedirURL(r)
	tokenRespBody, err := h.getBytesFromSuccessfullPost(h.openID.TokenURL,
		url.Values{"redirect_uri": {redirectURL},
			"code":          {authCode},
			"grant_type":    {"authorization_code"},
			"client_id":     {h.openID.ClientID},
			"client_secret": {h.openID.ClientSecret},
		})
	if err != nil {
		log.Printf("err=%s", err)
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}

	var oauth2AccessToken accessToken
	err = json.Unmarshal(tokenRespBody, &oauth2AccessToken)
	if err != nil {
		log.Printf(string(tokenRespBody))
		http.Error(w, "cannot decode oath2 response for token ", http.StatusInternalServerError)
		return
	}
	// TODO: tolower
	if oauth2AccessToken.TokenType != "Bearer" || len(oauth2AccessToken.AccessToken) < 1 {
		log.Printf(string(tokenRespBody))
		http.Error(w, "invalid accessToken ", http.StatusInternalServerError)
		return
	}

	// Now we use the access_token (from token exchange) to get userinfo
	userInfoRespBody, err := h.getBytesFromSuccessfullPost(h.openID.UserinfoURL,
		url.Values{"access_token": {oauth2AccessToken.AccessToken}})
	if err != nil {
		log.Printf("err=%s", err)
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}
	var userInfo openidConnectUserInfo
	err = json.Unmarshal(userInfoRespBody, &userInfo)
	if err != nil {
		log.Printf(string(tokenRespBody))
		http.Error(w, "cannot decode oath2 userinfo token ", http.StatusInternalServerError)
		return
	}
	username := getUsernameFromUserinfo(userInfo)

	err = h.setAndStoreAuthCookie(w, r, username, time.Now().Add(authNCookieExpirationDuration))
	if err != nil {
		log.Println(err)
		http.Error(w, "cannot set auth Cookie", http.StatusInternalServerError)
		return
	}

	destinationPath := inboundJWT.ReturnURL
	http.Redirect(w, r, destinationPath, http.StatusFound)
}

func (h *AuthNHandler) verifyAuthnCookie(cookieValue string, issuer string) (AuthInfo, bool, error) {
	if len(cookieValue) < 1 {
		return AuthInfo{}, false, nil
	}
	inboundJWT := AuthInfo{}
	tok, err := jwt.ParseSigned(cookieValue)
	if err != nil {
		return inboundJWT, false, nil
	}
	if err := h.JWTClaims(tok, &inboundJWT); err != nil {
		log.Printf("error parsing claims err=%s", err)
		return inboundJWT, false, nil
	}
	subject := "state:" + h.authCookieName
	if inboundJWT.Issuer != issuer || inboundJWT.Subject != subject ||
		inboundJWT.NotBefore > time.Now().Unix() || inboundJWT.Expiration < time.Now().Unix() {
		err = errors.New("invalid JWT values")
		return inboundJWT, false, nil
	}
	authInfo := inboundJWT
	authInfo.ExpiresAt = time.Unix(inboundJWT.Expiration, 0)
	return authInfo, true, nil
}

func (h *AuthNHandler) getRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {
	// If you have a verified cert, no need for cookies
	if r.TLS != nil {
		if len(r.TLS.VerifiedChains) > 0 {
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			return clientName, nil
		}
	}

	remoteCookie, err := r.Cookie(h.authCookieName)
	if err != nil {
		//s.logger.Debugf(1, "Err cookie %s", err)
		h.oauth2DoRedirectoToProviderHandler(w, r)
		return "", err
	}

	authInfo, ok, err := h.verifyAuthnCookie(remoteCookie.Value, r.Host)
	if err != nil {
		return "", err
	}

	if !ok {
		h.oauth2DoRedirectoToProviderHandler(w, r)
		return "", errors.New("Cookie not found")
	}
	if authInfo.ExpiresAt.Before(time.Now()) {
		h.oauth2DoRedirectoToProviderHandler(w, r)
		return "", errors.New("Expired Cookie")
	}
	return authInfo.Username, nil
}

func NewAuthNHandler(handler http.Handler, openIDConfig OpenIDConfig, sharedSecrets []string) http.Handler {
	rvalue := AuthNHandler{
		handler:        handler,
		authCookieName: cookieNamePrefix,
		openID:         openIDConfig,
		SharedSecrets:  sharedSecrets,
		netClient: &http.Client{
			Timeout: time.Second * 15,
		},
	}
	return &rvalue
}

func (h *AuthNHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//log.Printf("Inside the handler path=%s redir=%s", r.URL.Path, oauth2redirectPath)
	if strings.HasPrefix(r.URL.Path, oauth2redirectPath) {
		h.oauth2RedirectPathHandler(w, r)
		return
	}

	authUser, err := h.getRemoteUserName(w, r)
	if err != nil {
		return
	}
	r.Header.Set("X-Remote-User", authUser)

	h.handler.ServeHTTP(w, r)
}
