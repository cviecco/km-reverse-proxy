package authnHandler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Symantec/keymaster/lib/instrumentedwriter"
)

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

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

type httpTestLogger struct {
	//Username      string
	//LastLogRecord *instrumentedwriter.LogRecord
}

func (l httpTestLogger) Log(record instrumentedwriter.LogRecord) {
	//l.LastLogRecord = &record
	//l.Username = record.Username

	fmt.Printf("%s -  %s [%s] \"%s %s %s\" %d %d \"%s\"\n",
		record.Ip, record.Username, record.Time, record.Method,
		record.Uri, record.Protocol, record.Status, record.Size, record.UserAgent)

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
		r.Host = "localhost"
		username, err := handler.(*AuthNHandler).getRemoteUserName(w, r)
		if err != nil {
			t.Fatal("getRemoteUsername should NOT have failed")
		}
		if username != testUsername {
			t.Fatal("getRemoteUsername username does NOT match")
		}
	}, http.StatusOK)

}

func TestAutnnHandlerValid(t *testing.T) {
	sharedSecrets := []string{"secret"}
	openIDConfig := OpenIDConfig{}
	handler := NewAuthNHandler(NewTestHandler(), openIDConfig, sharedSecrets)

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
	goodCookieReq.Host = "localhost"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, goodCookieReq)
	if rr.Code != http.StatusOK {
		t.Fatal("Authentication Failed")
	}
	// now at should get a redirect if reaching the redirecturl
	oauth2redirectReq, err := http.NewRequest("GET", oauth2redirectPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, oauth2redirectReq)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatal("Ouath2 redirect did not failed")
	}
	// now we test with a wrapped handler to ensure username is set
	l := httpTestLogger{}
	wrappedHandler := instrumentedwriter.NewLoggingHandler(handler, l)
	rr3 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr3, goodCookieReq)
	if rr3.Code != http.StatusOK {
		t.Fatal("Authentication Failed")
	}
	// TODO: verify username injected is the one we expect

	// finaly we put a bad cookie
	badCookie := validCookie
	badCookie.Value = "Foo"
	badCookieReq, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	badCookieReq.AddCookie(validCookie)
	badCookieReq.Host = "localhost"
	rr4 := httptest.NewRecorder()
	handler.ServeHTTP(rr4, badCookieReq)
	if rr4.Code != http.StatusFound {
		t.Fatal("Bad cookie should redirect")
	}

}
