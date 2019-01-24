package authnHandler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type TestHandler struct {
}

func (h *TestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	okHandler(w, r)
}

func okHandler(w http.ResponseWriter, req *http.Request) {
	//w.(*LoggingWriter).SetCustomLogRecord("x-user-id", "1")
	w.Write([]byte(`ok`))
}

func NewTestHandler() http.Handler {
	return &TestHandler{}
}

func checkRequestHandlerCode(req *http.Request, handlerFunc http.HandlerFunc, expectedStatus int) (*httptest.ResponseRecorder, error) {
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlerFunc)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != expectedStatus {
		errStr := fmt.Sprintf("handler returned wrong status code: got %v want %v",
			status, expectedStatus)
		err := errors.New(errStr)
		return nil, err
	}
	return rr, nil
}

func TestOauth2RedirectHandlerSucccess(t *testing.T) {

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{\"access_token\": \"6789\", \"token_type\": \"Bearer\",\"username\":\"user\"}")
	}))
	defer ts.Close()

	sharedSecrets := []string{"secret"}
	openIDConfig := OpenIDConfig{
		TokenURL:    ts.URL,
		UserinfoURL: ts.URL}
	handler := NewAuthNHandler(NewTestHandler(), openIDConfig, sharedSecrets)
	handler.(*AuthNHandler).netClient = ts.Client()

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	stateString, err := handler.(*AuthNHandler).generateValidStateString(req)
	if err != nil {
		t.Fatal(err)
	}
	v := url.Values{
		"state": {stateString},
		"code":  {"12345"},
	}
	redirReq, err := http.NewRequest("GET", "/?"+v.Encode(), nil)
	rr := httptest.NewRecorder()
	handler.(*AuthNHandler).oauth2RedirectPathHandler(rr, redirReq)
	if rr.Code != http.StatusFound {
		t.Fatal("Response should have been a redirect")
	}
	resp := rr.Result()
	//body, _ := ioutil.ReadAll(resp.Body)
	//t.Logf("body =%s", string(body))
	if resp.Header.Get("Location") != "/" {
		t.Fatal("Response should have been a redirect to /")
	}
}

func TestGetRemoteUserNameHandler(t *testing.T) {
	sharedSecrets := []string{"secret"}
	openIDConfig := OpenIDConfig{}
	handler := NewAuthNHandler(NewTestHandler(), openIDConfig, sharedSecrets)

	// Test with no cookies... inmediate redirect
	urlList := []string{"/", "/static/foo"}
	for _, url := range urlList {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = checkRequestHandlerCode(req, func(w http.ResponseWriter, r *http.Request) {
			_, err := handler.(*AuthNHandler).getRemoteUserName(w, r)
			if err == nil {
				t.Fatal("getRemoteUsername should have failed")
			}
		}, http.StatusFound)
		if err != nil {
			t.Fatal(err)
		}

	}
	// Now fail with an unknown cookie
	uknownCookieReq, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	cookieVal, err := randomStringGeneration()
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: handler.(*AuthNHandler).authCookieName, Value: cookieVal}
	uknownCookieReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(uknownCookieReq, func(w http.ResponseWriter, r *http.Request) {
		_, err := handler.(*AuthNHandler).getRemoteUserName(w, r)
		if err == nil {
			t.Fatal("getRemoteUsername should have failed")
		}
	}, http.StatusFound)

	//now success with valid cookie
	goodCookieReq, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	const testUsername = "username"
	validCookie, err := handler.(*AuthNHandler).GenValidAuthCookie(testUsername)
	if err != nil {
		t.Fatal(err)
	}
	goodCookieReq.AddCookie(validCookie)
	_, err = checkRequestHandlerCode(goodCookieReq, func(w http.ResponseWriter, r *http.Request) {
		username, err := handler.(*AuthNHandler).getRemoteUserName(w, r)
		if err != nil {
			t.Fatal("getRemoteUsername should NOT have failed")
		}
		if username != testUsername {
			t.Fatal("getRemoteUsername username does NOT match")
		}
	}, http.StatusOK)

}
