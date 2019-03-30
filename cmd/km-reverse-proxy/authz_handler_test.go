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
