package main

import (
	"bufio"
	"errors"
	"os"

	//"github.com/Symantec/cloud-gate/lib/constants"
	"gopkg.in/yaml.v2"
)

type BaseConfig struct {
	ServicePort                 uint16 `yaml:"service_port"`
	TLSCertFilename             string `yaml:"tls_cert_filename"`
	TLSKeyFilename              string `yaml:"tls_key_filename"`
	ReverseProxyURL             string `yaml:"reverse_proxy_url"`
	ClientCAFilename            string `yaml:"client_ca_filename"`
	ClusterSharedSecretFilename string `yaml:"cluster_shared_secret_filename"`
	SharedSecrets               []string
}

type OpenIDConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	ProviderURL  string `yaml:"provider_url"`
	AuthURL      string `yaml:"auth_url"`
	TokenURL     string `yaml:"token_url"`
	UserinfoURL  string `yaml:"userinfo_url"`
	Scopes       string `yaml:"scopes"`
}

type UserInfoLDAPSource struct {
	BindUsername       string   `yaml:"bind_username"`
	BindPassword       string   `yaml:"bind_password"`
	LDAPTargetURLs     string   `yaml:"ldap_target_urls"`
	UserSearchBaseDNs  []string `yaml:"user_search_base_dns"`
	UserSearchFilter   string   `yaml:"user_search_filter"`
	GroupSearchBaseDNs []string `yaml:"group_search_base_dns"`
	GroupSearchFilter  string   `yaml:"group_search_filter"`
}

type StaticConfiguration struct {
	Base   BaseConfig
	OpenID OpenIDConfig
	Ldap   UserInfoLDAPSource
}

func getClusterSecretsFile(clusterSecretsFilename string) ([]string, error) {
	file, err := os.Open(clusterSecretsFilename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var rarray []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		rarray = append(rarray, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rarray) < 1 {
		return nil, errors.New("empty cluster secretFile")
	}
	return rarray, nil
}

func LoadVerifyConfigFile(configFilename string) (*StaticConfiguration, error) {
	var config StaticConfiguration
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return nil, err
	}
	source, err := os.Open(configFilename)
	if err != nil {
		return nil, err

	}
	err = yaml.NewDecoder(source).Decode(&config)
	if err != nil {
		return nil, err
	}
	// setup defaults
	if config.Base.ServicePort == 0 {
		config.Base.ServicePort = 22443
		//constants.DefaultStatusPort
	}
	/*
	   if len(config.Base.AccountConfigurationUrl) == 0 {
	           config.Base.AccountConfigurationUrl =
	                   constants.DefaultAccountConfigurationUrl
	   }
	   if config.Base.AccountConfigurationCheckInterval == 0 {
	           config.Base.AccountConfigurationCheckInterval =
	                   constants.DefaultAccountConfigurationCheckInterval
	   }
	*/
	// Verify oauth2 setup
	if len(config.OpenID.AuthURL) < 1 ||
		len(config.OpenID.TokenURL) < 1 ||
		len(config.OpenID.UserinfoURL) < 1 ||
		len(config.OpenID.Scopes) < 1 ||
		len(config.OpenID.ClientID) < 1 {
		return nil, errors.New("invalid openid config")
	}

	// Verify shared secrets
	if len(config.Base.ClusterSharedSecretFilename) < 0 {
		return nil, errors.New("missing shared cluster secrets")
	}
	config.Base.SharedSecrets, err = getClusterSecretsFile(config.Base.ClusterSharedSecretFilename)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
