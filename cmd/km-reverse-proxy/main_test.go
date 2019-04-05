package main

import (
	//"errors"
	//"fmt"
	"io/ioutil"
	//"net/http"
	//"net/http/httptest"
	//"net/url"
	"os"
	"os/user"
	"testing"

	"github.com/cviecco/km-reverse-proxy/authnHandler"
	"gopkg.in/yaml.v2"
)

func generateTmpFileWithContent(t *testing.T, fileContent []byte) (filename string) {
	file, err := ioutil.TempFile("/tmp", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	//defer os.Remove(file.Name())
	_, err = file.Write(fileContent)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Sync()
	if err != nil {
		t.Fatal(err)
	}
	return file.Name()
}

func generateTmpSecretsFile(t *testing.T) (filename string) {
	return generateTmpFileWithContent(t, []byte("secret\n"))
}

func generateTmpPathConfigFile(t *testing.T) (filename string) {
	user, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := AuthZHandler{
		userInfo: make(map[string]UserInfoCacheEntry),
	}
	userGroups, err := h.getUserGroups_os(user.Username)
	if err != nil {
		t.Fatal(err)
	}
	authzConfig := AuthZConfiguration{
		ProtectedPaths: []ProtectedPath{
			ProtectedPath{
				Path:          "/",
				AllowedGroups: userGroups,
			},
		},
	}
	configText, err := yaml.Marshal(&authzConfig)
	if err != nil {
		t.Fatal(err)
	}
	return generateTmpFileWithContent(t, []byte(configText))
}

const testOpenIDURL = "https://localhost:10444"

func TestGetServerFromConfigSuccess(t *testing.T) {
	secretsFilename := generateTmpSecretsFile(t)
	defer os.Remove(secretsFilename)
	pathConfigFilename := generateTmpPathConfigFile(t)
	defer os.Remove(pathConfigFilename)
	/*
		tlsCertFilename := generateTmpFileWithContent(t, localhostCertPem)
		defer os.Remove(tlsCertFilename)
		tlsKeyFilename := generateTmpFileWithContent(t, localhostKeyPem)
		defer os.Remove(tlsKeyFilename)
	*/
	staticConfig := StaticConfiguration{
		Base: BaseConfig{
			ServicePort:                 10443,
			PathConfigLocation:          pathConfigFilename,
			ClusterSharedSecretFilename: secretsFilename,
		},
		OpenID: authnHandler.OpenIDConfig{
			ClientID:     "foo",
			ClientSecret: "fooSecret",
			ProviderURL:  testOpenIDURL + "/provider",
			AuthURL:      testOpenIDURL + "/auth",
			TokenURL:     testOpenIDURL + "/token",
			UserinfoURL:  testOpenIDURL + "/userinfo",
			Scopes:       "openid email profile",
		},
	}
	_, err := getServerFromConfig(&staticConfig)
	if err != nil {
		t.Fatal(err)
	}
}
