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

	"github.com/k1LoW/tcpdp/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	probeDumper string
)

const snaplenAuto = "auto"
const snaplenDefault = 0xFFFF

// probeCmd represents the probe command
var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe mode",
	Long:  "`tcp prove` dump packets like tcpdump.",
	Run: func(cmd *cobra.Command, args []string) {
		err := viper.ReadInConfig()
		if err != nil {
			logger.Warn("Config file not found.", zap.Error(err))
		}
		if cfgFile == "" {
			viper.Set("tcpdp.dumper", probeDumper) // because share with `server`
		}

		dumper := viper.GetString("tcpdp.dumper")
		target := viper.GetString("probe.target")
		device := viper.GetString("probe.interface")
		bufferSize := viper.GetString("probe.bufferSize")
		immediateMode := viper.GetBool("probe.immediateMode")
		snapshotLength := viper.GetString("probe.snapshotLength")
		ifi, err := net.InterfaceByName(device)
		if err != nil {
			logger.Fatal("interface error.", zap.Error(err))
		}
		mtu := ifi.MTU
		if snapshotLength == snaplenAuto {
			snapshotLength = fmt.Sprintf("%dB (auto)", mtu+14+4) // 14:Ethernet header 4:FCS
			viper.Set("probe.snapshotLength", fmt.Sprintf("%dB", mtu+14+4))
		}
		internalBufferLength := viper.GetInt("probe.internalBufferLength")

		defer logger.Sync()

		signalChan := make(chan os.Signal, 1)
		signal.Ignore()
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

		s := server.NewProbeServer(context.Background(), logger)

		logger.Info("Starting probe.",
			zap.String("dumper", dumper),
			zap.String("interface", device),
			zap.String("mtu", fmt.Sprintf("%d", mtu)),
			zap.String("probe_target_addr", target),
			zap.String("buffer_size", bufferSize),
			zap.Bool("immediate_mode", immediateMode),
			zap.String("snapshot_length", snapshotLength),
			zap.Int("internal_buffer_length", internalBufferLength),
		)

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
	probeCmd.Flags().StringP("target", "t", "", "target addr. (ex. \"localhost:80\", \"3306\")")
	probeCmd.Flags().StringP("interface", "i", "", "interface")
	probeCmd.Flags().StringP("buffer-size", "B", "2MB", "buffer size (pcap_buffer_size)")
	probeCmd.Flags().BoolP("immediate-mode", "", false, "immediate mode")
	probeCmd.Flags().StringP("snapshot-length", "s", fmt.Sprintf("%dB", snaplenDefault), "snapshot length")
	probeCmd.Flags().StringVarP(&probeDumper, "dumper", "d", "hex", "dumper")

	if err := viper.BindPFlag("probe.target", probeCmd.Flags().Lookup("target")); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("probe.interface", probeCmd.Flags().Lookup("interface")); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("probe.bufferSize", probeCmd.Flags().Lookup("buffer-size")); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("probe.immediateMode", probeCmd.Flags().Lookup("immediate-mode")); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("probe.snapshotLength", probeCmd.Flags().Lookup("snapshot-length")); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rootCmd.AddCommand(probeCmd)
}
