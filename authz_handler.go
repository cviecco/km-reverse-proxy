package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

type ProtectedPath struct {
	Path          string   `yaml:"path"`
	AllowedGroups []string `yaml:"allowed_groups"`
	AllowedUsers  []string `yaml:"allowed_users"`
}

type AuthZConfiguration struct {
	ProtectedPaths []ProtectedPath `yaml:"protected_paths"`
}

type UserInfoCacheEntry struct {
	Expiration time.Time
	Groups     []string
}

type AuthZHandler struct {
	handler        http.Handler
	configLocation string
	currentConfig  *AuthZConfiguration
	//TODO: mutex
	userinfoMutex sync.Mutex
	userInfo      map[string]UserInfoCacheEntry
}

func (h *AuthZHandler) LoadConfig() error {
	var config AuthZConfiguration
	if _, err := os.Stat(h.configLocation); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return err
	}
	source, err := os.Open(h.configLocation)
	if err != nil {
		return err

	}
	err = yaml.NewDecoder(source).Decode(&config)
	if err != nil {
		return err
	}
	for _, pathConfig := range config.ProtectedPaths {
		sort.Strings(pathConfig.AllowedGroups)
		sort.Strings(pathConfig.AllowedUsers)
	}
	sort.SliceStable(config.ProtectedPaths,
		func(i, j int) bool { return config.ProtectedPaths[i].Path < config.ProtectedPaths[j].Path })
	h.currentConfig = &config
	log.Printf("%+v", config)
	return nil
}

func (h *AuthZHandler) getUserGroups_os(username string) ([]string, error) {
	currentUser, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	groupIDs, err := currentUser.GroupIds()
	if err != nil {
		return nil, err
	}
	var groupNames []string
	for _, groupID := range groupIDs {
		group, err := user.LookupGroupId(groupID)
		if err != nil {
			continue
		}
		groupNames = append(groupNames, group.Name)
	}
	return groupNames, nil
}

func (h *AuthZHandler) getUserGroups(username string) ([]string, error) {
	//try from cache
	userinfo, ok := h.userInfo[username]
	if ok && userinfo.Expiration.After(time.Now()) {
		return userinfo.Groups, nil
	}
	usergroups, err := h.getUserGroups_os(username)
	if err != nil {
		return userinfo.Groups, nil
	}
	userinfo.Groups = usergroups
	userinfo.Expiration = time.Now().Add(time.Second * 120)
	h.userInfo[username] = userinfo
	return usergroups, nil

}

func (h *AuthZHandler) canUserAccessRequest(username string, r *http.Request) (bool, error) {
	userGroups, err := h.getUserGroups(username)
	if err != nil {
		return false, err
	}
	sort.Strings(userGroups)
	cleanPath := path.Clean(r.URL.Path)
	for _, pathConfig := range h.currentConfig.ProtectedPaths {
		if !strings.HasPrefix(cleanPath, pathConfig.Path) {
			continue
		}
		allowedGroupLen := len(pathConfig.AllowedGroups)
		for _, groupName := range userGroups {
			groupIndex := sort.SearchStrings(pathConfig.AllowedGroups, groupName)
			if groupIndex >= allowedGroupLen {
				continue
			}
			if pathConfig.AllowedGroups[groupIndex] == groupName {
				log.Printf("allowedGroup=%s, gropIndex=%d, allowedGroups=%s", groupName, groupIndex, pathConfig.AllowedGroups)
				return true, nil
			}
		}

	}
	return false, nil
}

func NewAuthZHandler(handler http.Handler, configLocation string) http.Handler {
	return &AuthZHandler{
		handler:        handler,
		configLocation: configLocation,
		userInfo:       make(map[string]UserInfoCacheEntry),
	}
}

func (h *AuthZHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Inside the handler (auntz) path=%s", r.URL.Path)

	authUser := r.Header.Get("X-Remote-User")
	if authUser == "" {
		http.Error(w, "bad username translation", http.StatusUnauthorized)
		return
	}
	accessOK, err := h.canUserAccessRequest(authUser, r)
	if err != nil {
		http.Error(w, "bad username translation", http.StatusInternalServerError)
		return
	}
	if !accessOK {
		http.Error(w, "Access not allowed", http.StatusForbidden)
		return
	}

	h.handler.ServeHTTP(w, r)
}
