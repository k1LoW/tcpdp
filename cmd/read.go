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
	"io/ioutil"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/dumper/hex"
	"github.com/k1LoW/tcpdp/dumper/mysql"
	"github.com/k1LoW/tcpdp/dumper/pg"
	"github.com/k1LoW/tcpdp/reader"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	readDumper string
	readTarget string
)

const readIternalBufferLength = 10000

// readCmd represents the read command
var readCmd = &cobra.Command{
	Use:   "read [PCAP]",
	Short: "Read pcap file mode",
	Long:  "Read pcap format file and dump.",
	Args: func(cmd *cobra.Command, args []string) error {
		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) != 0 {
			if len(args) != 1 {
				return fmt.Errorf("Error: %s", "requires pcap file path")
			}
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		viper.Set("tcpdp.dumper", readDumper) // because share with `server`
		viper.Set("log.enable", false)
		viper.Set("log.stdout", false)
		viper.Set("dumpLog.enable", false)
		viper.Set("dumpLog.stdout", true)

		defer logger.Sync()

		var pcapFile string

		fi, _ := os.Stdin.Stat()

		if (fi.Mode() & os.ModeCharDevice) != 0 {
			pcapFile = args[0]
		} else {
			pcap, _ := ioutil.ReadAll(os.Stdin)
			tmpfile, _ := ioutil.TempFile("", "tcpdptmp")
			defer func() {
				if err := tmpfile.Close(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				if err := os.Remove(tmpfile.Name()); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}()
			pcapFile = tmpfile.Name()
			if _, err := tmpfile.Write(pcap); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		handle, err := pcap.OpenOffline(pcapFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer handle.Close()

		var d dumper.Dumper
		switch readDumper {
		case "hex":
			d = hex.NewDumper()
		case "pg":
			d = pg.NewDumper()
		case "mysql":
			d = mysql.NewDumper()
		default:
			d = hex.NewDumper()
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		ctx, cancel := context.WithCancel(context.Background())

		proxyProtocol := viper.GetBool("tcpdp.proxyProtocol")

		r := reader.NewPacketReader(
			ctx,
			cancel,
			packetSource,
			d,
			[]dumper.DumpValue{},
			logger,
			readIternalBufferLength,
			proxyProtocol,
		)

		t, err := reader.ParseTarget(readTarget)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := r.ReadAndDump(t); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() {
	readCmd.Flags().StringVarP(&readTarget, "target", "t", "", "target addr. (ex. \"localhost:80\", \"3306\")")
	readCmd.Flags().StringP("format", "f", "json", "STDOUT format. (\"console\", \"json\" , \"ltsv\") ")
	readCmd.Flags().StringVarP(&readDumper, "dumper", "d", "hex", "dumper")

	if err := viper.BindPFlag("dumpLog.stdoutFormat", readCmd.Flags().Lookup("format")); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rootCmd.AddCommand(readCmd)
}
