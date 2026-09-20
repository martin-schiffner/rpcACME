package config

import (
	"github.com/spf13/viper"
)

type (
	Config struct {
		HTTP          HTTPConfig
		AcmeConfig    AcmeConfig `mapstructure:"acme"`
		Database      DatabaseConfig
		Rpcca         RpccaConfig
		CaCertsFile   string `mapstructure:"ca_certs_file"`
		EncryptionKey string `mapstructure:"encryption_key"`
	}

	HTTPConfig struct {
		ListenIP   string `mapstructure:"listen_ip"`
		ListenPort uint16 `mapstructure:"listen_port"`
		BaseUrl    string `mapstructure:"base_url"`
		TLS        struct {
			Enabled         bool
			CertificatePath string `mapstructure:"certificate_path"`
			KeyPath         string `mapstructure:"key_path"`
		}
	}

	AcmeEndpointLimits struct {
		MaxCertsPerUser int `mapstructure:"max_certs_per_user"`
		RenewalStart    int `mapstructure:"renewal_start"`
	}

	AcmeEndpointConfig struct {
		Ca             string   `mapstructure:"ca"`
		CaName         string   `mapstructure:"ca_name"`
		Template       string   `mapstructure:"template"`
		ChallengeTypes []string `mapstructure:"challenge_types"`
	}

	AcmeConfig struct {
		Limits    AcmeEndpointLimits            `mapstructure:"limits"`
		Endpoints map[string]AcmeEndpointConfig `mapstructure:"endpoints"`
	}

	DatabaseConfig struct {
		Hostname      string
		Port          uint16
		Database      string
		Username      string
		Password      string
		ConnectionUri string `mapstructure:"connection_uri"`
	}

	RpccaConfig struct {
		Hostname string
		Port     uint16
		CaFile   string `mapstructure:"ca_file"`
		CaName   string `mapstructure:"ca_name"`
		KeyType  string `mapstructure:"key_type"`
	}
)

func GetConfig() (Config, error) {
	var config Config

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("../config")

	err := viper.ReadInConfig()

	if err != nil {
		return config, err
	}

	err = viper.Unmarshal(&config)

	if err != nil {
		return config, err
	}

	return config, nil
}
