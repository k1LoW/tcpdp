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
	"context"
	"os"
	"os/signal"
	"syscall"

	"fmt"
	"github.com/k1LoW/tcprxy/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	probeDumper string
)

// probeCmd represents the probe command
var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "probe",
	Long:  `probe`,
	Run: func(cmd *cobra.Command, args []string) {
		err := viper.ReadInConfig()
		if err != nil {
			logger.Warn("Config file not found.", zap.Error(err))
		}
		viper.Set("proxy.dumper", probeDumper) // because share with `server`

		target := viper.GetString("probe.target")
		device := viper.GetString("probe.interface")

		defer logger.Sync()

		signalChan := make(chan os.Signal, 1)
		signal.Ignore()
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

		s := server.NewProbeServer(context.Background(), logger)

		logger.Info(fmt.Sprintf("Starting probe. %s %s", device, target))
		go s.Start()

		sc := <-signalChan

		switch sc {
		case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
			logger.Info("Shutting down probe...")
			s.Shutdown()
			<-s.ClosedChan
		default:
			logger.Info("Unexpected signal")
			os.Exit(1)
		}
	},
}

func init() {
	probeCmd.Flags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	probeCmd.Flags().StringP("target", "t", "localhost:80", "target addr")
	probeCmd.Flags().StringP("interface", "i", "", "interface")
	probeCmd.Flags().StringVarP(&probeDumper, "dumper", "d", "hex", "dumper")

	viper.BindPFlag("probe.target", probeCmd.Flags().Lookup("target"))
	viper.BindPFlag("probe.interface", probeCmd.Flags().Lookup("interface"))

	rootCmd.AddCommand(probeCmd)
}
