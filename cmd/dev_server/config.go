package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/caarlos0/env/v6"
)

type TimeSeconds time.Duration

func (t *TimeSeconds) UnmarshalText(text []byte) error {
	tt, err := strconv.Atoi(string(text))
	*t = TimeSeconds(tt * int(time.Second))
	return err
}

type TimeMiliseconds time.Duration

func (t *TimeMiliseconds) UnmarshalText(text []byte) error {
	tt, err := strconv.Atoi(string(text))
	*t = TimeMiliseconds(tt * int(time.Millisecond))
	return err
}

type Config struct {
	EtcdHosts          []string        `env:"ETCD_HOSTS" envSeparator:";" envDefault:"localhost:2379"`
	EtcdInitTimeout    TimeSeconds     `env:"ETCD_INIT_TIMEOUT" envDefault:"2"`
	EtcdDialTimeout    TimeSeconds     `env:"ETCD_DIAL_TIMEOUT" envDefault:"5"`
	EtcdContextTimeout TimeMiliseconds `env:"ETCD_CONTEXT_TIMEOUT" envDefault:"100"`

	KnoxHosts       []string `env:"KNOX_DNS" envSeparator:";" envDefault:"localhost:9000"`
	IsDevServer     bool     `env:"DEV_SERVER" envDefault:"true"`
	RSAPubKey       string   `env:"RSA_PUBLIC_KEY,notEmpty"`
	DbEncryptionKey string   `env:"DB_ENCRYPTION_KEY,unset" envDefault:"testtesttesttest"`
	Version         string   `env:"VERSION,notEmpty"`
	MySqlPassword   string   `env:"MYSQL_PASSWORD,unset"`
	DbType          string   `env:"DB_TYPE" envDefault:"mysql"`
	SpiffeCAPath    string   `env:"SPIFFE_CA_PATH" envDefault:"/certs/bundle.crt"`
	SpiffeCA        string   `env:"SPIFFE_CA,file" envDefault:"${SPIFFE_CA_PATH}" envExpand:"true"`
}

func ReadKnoxConfig() (*Config, error) {
	config := Config{}

	err := env.Parse(&config)
	if err != nil {
		return nil, fmt.Errorf("read config error: %w", err)
	}

	if err = verifyConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func verifyConfig(config *Config) error {
	if !config.IsDevServer {
		if config.DbType == "mysql" && config.MySqlPassword == "" {
			return fmt.Errorf("mysql password is not set")
		}
		if config.DbType == "etcd" && len(config.EtcdHosts) == 0 {
			return fmt.Errorf("etcd hosts are not set")
		}
		if config.SpiffeCA == "" {
			return fmt.Errorf("spiffe certs are not set")
		}
	}
	return nil
}
