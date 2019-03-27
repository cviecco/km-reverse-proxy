package main

import (
	//"errors"
	//"fmt"
	"io/ioutil"
	//"net/http"
	//"net/http/httptest"
	//"net/url"
	"os"
	//"os/user"
	"testing"

	"github.com/cviecco/km-reverse-proxy/authnHandler"
	"gopkg.in/yaml.v2"
)

func TestGetClusterSecretsFile(t *testing.T) {
	file, err := ioutil.TempFile("/tmp", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	_, err = getClusterSecretsFile(file.Name())
	if err == nil {
		t.Fatal(err)
	}
	_, err = file.Write([]byte("secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	err = file.Sync()
	if err != nil {
		t.Fatal(err)
	}
	_, err = getClusterSecretsFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadVerifyConfigFile(t *testing.T) {
	secretsFile, err := ioutil.TempFile("/tmp", "secretsFile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(secretsFile.Name())
	_, err = secretsFile.Write([]byte("secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	err = secretsFile.Sync()
	if err != nil {
		t.Fatal(err)
	}
	baseConfig := BaseConfig{ClusterSharedSecretFilename: secretsFile.Name()}
	openidConfig := authnHandler.OpenIDConfig{
		AuthURL:     "https://www.example.com/authorize",
		TokenURL:    "https://www.example.com/token",
		UserinfoURL: "https://www.example.com/userinfo",
		Scopes:      "openid mail",
		ClientID:    "client_id",
	}

	ouboundConfig := &StaticConfiguration{
		Base:   baseConfig,
		OpenID: openidConfig,
	}
	configFile, err := ioutil.TempFile("/tmp", "configFile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile.Name())
	_, err = LoadVerifyConfigFile(configFile.Name())
	if err == nil {
		t.Fatal(err)
	}
	configBytes, err := yaml.Marshal(ouboundConfig)
	if err != nil {
		t.Fatal(err)
	}
	_, err = configFile.Write(configBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = configFile.Sync()
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadVerifyConfigFile(configFile.Name())
	if err != nil {
		t.Fatal(err)
	}
}
