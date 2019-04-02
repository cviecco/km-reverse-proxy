package main

import (
	//"errors"
	//"fmt"
	"io/ioutil"
	"net/http"
	//"net/http/httptest"
	//"net/url"
	"os"
	"os/user"
	"testing"
)

const testConfigFileContent = `#comment
protected_paths:
  - path: "/"
    allowed_groups: ["group1", "group2"]
  - path: "/foobar"
    allowed_groups: ["group1", "group3"]
`

func TestLoadConfig(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(testConfigFileContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}
	h := AuthZHandler{
		//handler:        handler,
		configLocation: tmpfile.Name(),
		//userInfo: make(map[string]UserInfoCacheEntry),
		//ldapConfig:     ldapConfig,
	}
	err = h.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetUserGroupsOSSuccess(t *testing.T) {
	user, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := AuthZHandler{
		//handler:        handler,
		//configLocation: configLocation,
		userInfo: make(map[string]UserInfoCacheEntry),
		//ldapConfig:     ldapConfig,
	}
	_, err = h.getUserGroups_os(user.Username)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetUserGroupsSuccess(t *testing.T) {
	user, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := AuthZHandler{
		//handler:        handler,
		//configLocation: configLocation,
		userInfo: make(map[string]UserInfoCacheEntry),
		//ldapConfig:     ldapConfig,
	}
	_, err = h.getUserGroups(user.Username)
	if err != nil {
		t.Fatal(err)
	}
	//ensure cache exits
	validEntry, ok := h.userInfo[user.Username]
	if !ok {
		t.Fatal(err)
	}
	//force a cache entry and test
	const testCacheOnlyUsername = "foobarbaz"
	h.userInfo[testCacheOnlyUsername] = validEntry
	_, err = h.getUserGroups(testCacheOnlyUsername)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCanUserAccessRequest(t *testing.T) {
	user, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := AuthZHandler{
		//handler:        handler,
		//configLocation: configLocation,
		userInfo: make(map[string]UserInfoCacheEntry),
		//ldapConfig:     ldapConfig,
	}
	userGroups, err := h.getUserGroups(user.Username)
	if err != nil {
		t.Fatal(err)
	}
	h.currentConfig = &AuthZConfiguration{
		ProtectedPaths: []ProtectedPath{
			ProtectedPath{
				Path:          "/protected",
				AllowedGroups: []string{"supercoolGroup"},
			},
			ProtectedPath{
				Path:          "/",
				AllowedGroups: userGroups,
			},
		},
	}
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.canUserAccessRequest(user.Username, req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("should have succeeded")
	}
	ok, err = h.canUserAccessRequest("randomuser", req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("should have failed")
	}
	req2, err := http.NewRequest("GET", "/protected/", nil)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = h.canUserAccessRequest(user.Username, req2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("should have failed")
	}

}
