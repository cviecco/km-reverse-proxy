package main

import (
	//"errors"
	//"fmt"
	//"net/http"
	//"net/http/httptest"
	//"net/url"
	"os/user"
	"testing"
)

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
