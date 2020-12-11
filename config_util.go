package main

import "github.com/Ptt-official-app/go-openbbsmiddleware/config_util"

const configPrefix = "openbbs-middleware"

func InitConfig() error {
	config()
	return nil
}

func setStringConfig(idx string, orig string) string {
	return config_util.SetStringConfig(configPrefix, idx, orig)
}
