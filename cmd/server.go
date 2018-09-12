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
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/k1LoW/tcprxy/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	serverDumper string
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "server",
	Long:  `server`,
	Run: func(cmd *cobra.Command, args []string) {
		err := viper.ReadInConfig()
		if err != nil {
			logger.Warn("Config file not found.", zap.Error(err))
		}
		viper.Set("proxy.dumper", serverDumper) // because share with `probe`

		listenAddr := viper.GetString("proxy.listenAddr")
		remoteAddr := viper.GetString("proxy.remoteAddr")
		useServerSterter := viper.GetBool("proxy.useServerSterter")

		defer logger.Sync()

		lAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
		if err != nil {
			logger.Fatal("error", zap.Error(err))
			os.Exit(1)
		}
		rAddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
		if err != nil {
			logger.Fatal("error", zap.Error(err))
			os.Exit(1)
		}

		signalChan := make(chan os.Signal, 1)
		signal.Ignore()
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

		s := server.NewServer(context.Background(), lAddr, rAddr, logger)

		if useServerSterter {
			logger.Info(fmt.Sprintf("Starting server. [server_starter] <-> %s:%d", rAddr.IP, rAddr.Port))
		} else {
			logger.Info(fmt.Sprintf("Starting server. %s:%d <-> %s:%d", lAddr.IP, lAddr.Port, rAddr.IP, rAddr.Port))
		}
		go s.Start()

		sc := <-signalChan

		switch sc {
		case syscall.SIGINT:
			logger.Info("Shutting down server...")
			s.Shutdown()
			s.Wg.Wait()
			<-s.ClosedChan
		case syscall.SIGQUIT, syscall.SIGTERM:
			logger.Info("Graceful Shutting down server...")
			s.GracefulShutdown()
			s.Wg.Wait()
			<-s.ClosedChan
		default:
			logger.Info("Unexpected signal")
			os.Exit(1)
		}
	},
}

func init() {
	serverCmd.Flags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	serverCmd.Flags().StringP("listen", "l", "localhost:8080", "listen address")
	serverCmd.Flags().StringP("remote", "r", "localhost:80", "remote address")
	serverCmd.Flags().StringVarP(&serverDumper, "dumper", "d", "hex", "dumper")
	serverCmd.Flags().BoolP("use-server-starter", "s", false, "use server_starter")

	viper.BindPFlag("proxy.listenAddr", serverCmd.Flags().Lookup("listen"))
	viper.BindPFlag("proxy.remoteAddr", serverCmd.Flags().Lookup("remote"))
	viper.BindPFlag("proxy.useServerSterter", serverCmd.Flags().Lookup("use-server-starter"))
	viper.BindPFlag("proxy.dumper", serverCmd.Flags().Lookup("dumper"))

	rootCmd.AddCommand(serverCmd)
}
