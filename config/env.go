package config

import "github.com/spf13/viper"

type Config struct {
	//POSTGRES
	POSTGRES_USER     string `mapstructure:"POSTGRES_USER"`
	POSTGRES_PASSWORD string `mapstructure:"POSTGRES_PASSWORD"`
	POSTGRES_DB       string `mapstructure:"POSTGRES_DB"`
	POSTGRES_HOST     string `mapstructure:"POSTGRES_HOST"`
	POSTGRES_PORT     string `mapstructure:"POSTGRES_PORT"`

	//REDIS
	REDIS_PORT     string `mapstructure:"REDIS_PORT"`
	REDIS_PASSWORD string `mapstructure:"REDIS_PASSWORD"`
	REDIS_HOST     string `mapstructure:"REDIS_HOST"`

	// HTTP Server
	SERVER_PORT string `mapstructure:"SERVER_PORT"`

	// JWT
	JWT_SECRET               string `mapstructure:"JWT_SECRET"`
	ACCESS_TOKEN_TTL_MINUTES int    `mapstructure:"ACCESS_TOKEN_TTL_MINUTES"`
	REFRESH_TOKEN_TTL_DAYS   int    `mapstructure:"REFRESH_TOKEN_TTL_DAYS"`

	// GoogleAuth
	GOOGLE_CLIENT_ID     string `mapstructure:"GOOGLE_CLIENT_ID"`
	GOOGLE_CLIENT_SECRET string `mapstructure:"GOOGLE_CLIENT_SECRET"`
	GOOGLE_REDIRECT_URL  string `mapstructure:"GOOGLE_REDIRECT_URL"`

	// OTP
	OTP_TTL_MINUTES int `mapstructure:"OTP_TTL_MINUTES"`
	OTP_LENGTH      int `mapstructure:"OTP_LENGTH"`

	// Session
	SESSION_SECRET string `mapstructure:"SESSION_SECRET"`
}

func LoadConfig() (c Config, err error) {
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()
	err = viper.ReadInConfig()
	if err != nil {
		return c, err
	}
	err = viper.Unmarshal(&c)
	return c, err
}
