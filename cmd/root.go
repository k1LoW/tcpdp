// Copyright © 2018 Ken'ichiro Oyama <k1lowxb@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"os"

	l "github.com/k1LoW/tcprxy/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	cfgFile string
	logger  *zap.Logger
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tcprxy",
	Short: "tcprxy",
	Long:  `tcprxy`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal("error", zap.Error(err))
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetDefault("proxy.useServerSterter", false)
	viper.SetDefault("proxy.listenAddr", "localhost:8080")
	viper.SetDefault("proxy.remoteAddr", "localhost:80")
	viper.SetDefault("proxy.dumper", "hex")

	viper.SetDefault("log.dir", ".")
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.rotateEnable", true)
	viper.SetDefault("log.rotationTime", "daily")
	viper.SetDefault("log.rotationCount", 7)

	viper.SetDefault("dumpLog.dir", ".")
	viper.SetDefault("dumpLog.format", "json")
	viper.SetDefault("dumpLog.rotateEnable", true)
	viper.SetDefault("dumpLog.rotationTime", "daily")
	viper.SetDefault("dumpLog.rotationCount", 7)

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("tcprxy")
		viper.AddConfigPath("/etc/tcprxy/")
		viper.AddConfigPath("$HOME/.tcprxy")
		viper.AddConfigPath(".")
	}
	err := viper.ReadInConfig()
	logger = l.NewLogger()

	if err != nil {
		logger.Warn("Config file not found.", zap.Error(err))
	}
}
