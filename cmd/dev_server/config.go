package main

import (
	"fmt"

	"github.com/caarlos0/env/v6"
)

type Config struct {
	CMName  string `env:"CM_NAME,notEmpty"`
	CRTName string `env:"CRT_NAME,notEmpty"`
}

func ReadKubeConfig() (*Config, error) {
	config := Config{}

	err := env.Parse(&config)
	if err != nil {
		return nil, fmt.Errorf("read config error: %w", err)
	}

	return &config, nil
}
