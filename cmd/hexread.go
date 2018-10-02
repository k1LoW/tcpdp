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
	"bufio"
	h "encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/dumper/mysql"
	"github.com/k1LoW/tcpdp/reader"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	hexreadTarget string
)

// hexreadCmd represents the hexread command
var hexreadCmd = &cobra.Command{
	Use:   "hexread",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if terminal.IsTerminal(0) {
			if len(args) != 1 {
				return fmt.Errorf("Error: %s", "requires pcap file path")
			}
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		viper.Set("log.enable", false)
		viper.Set("log.stdout", true)
		viper.Set("dumpLog.enable", false)
		viper.Set("dumpLog.stdout", true)

		host, port, err := reader.ParseTarget(hexreadTarget)
		if err != nil {
			panic(err)
		}

		var hexFile string
		if terminal.IsTerminal(0) {
			hexFile = args[0]
		} else {
			h, _ := ioutil.ReadAll(os.Stdin)
			tmpfile, _ := ioutil.TempFile("", "tcpdptmp")
			defer func() {
				tmpfile.Close()
				os.Remove(tmpfile.Name())
			}()
			hexFile = tmpfile.Name()
			if _, err := tmpfile.Write(h); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		fp, err := os.Open(hexFile)
		if err != nil {
			panic(err)
		}
		defer fp.Close()
		var d dumper.Dumper
		d = mysql.NewDumper()

		r := bufio.NewReader(fp)
		mMap := map[string]*dumper.ConnMetadata{}

		for {
			line, err := r.ReadBytes('\n')
			if err != nil && err != io.EOF {
				panic(err)
			}

			eof := err == io.EOF && len(line) == 0
			if eof {
				break
			}

			var log interface{}
			err = json.Unmarshal(line, &log)
			if err != nil {
				panic(err)
			}

			var directionStr string
			var connID string
			if log.(map[string]interface{})["direction"] != nil {
				directionStr = log.(map[string]interface{})["direction"].(string)
			}

			if log.(map[string]interface{})["conn_id"] != nil {
				connID = log.(map[string]interface{})["conn_id"].(string)
			}

			connMetadata, ok := mMap[connID]
			if !ok {
				connMetadata = d.NewConnMetadata()
				mMap[connID] = connMetadata // TODO: memory leak point
			}

			var direction dumper.Direction
			if directionStr == "" {
				srcAddr := log.(map[string]interface{})["src_addr"].(string)
				srcHost, srcPort, err := reader.ParseTarget(srcAddr)
				dstAddr := log.(map[string]interface{})["dst_addr"].(string)
				dstHost, dstPort, err := reader.ParseTarget(dstAddr)
				if err != nil {
					panic(err)
				}
				if (host == "" || dstHost == host) && dstPort == port {
					direction = dumper.SrcToDst
				} else if (host == "" || srcHost == host) && srcPort == port {
					direction = dumper.DstToSrc
				} else {
					direction = dumper.Unknown
				}
			} else {
				switch directionStr {
				case dumper.SrcToDst.String():
					direction = dumper.SrcToDst
				case dumper.DstToSrc.String():
					direction = dumper.DstToSrc
				default:
					direction = dumper.Unknown
				}
			}

			str := strings.Replace(log.(map[string]interface{})["bytes"].(string), " ", "", -1)
			in, err := h.DecodeString(str)
			if err != nil {
				logger.Warn("DecodeString error", zap.String("str", str), zap.Error(err))
				continue
			}
			values := d.Read(in, direction, connMetadata)

			if len(values) > 0 {
				delete(log.(map[string]interface{}), "bytes")
			}

			values = append(values, connMetadata.DumpValues...)
			for k, v := range log.(map[string]interface{}) {
				values = append(values, dumper.DumpValue{
					Key:   k,
					Value: v,
				})
			}

			d.Log(values)
		}
	},
}

func init() {
	hexreadCmd.Flags().StringVarP(&hexreadTarget, "target", "t", "", "target addr. (ex. \"localhost:80\", \"3306\")")
	rootCmd.AddCommand(hexreadCmd)
}
