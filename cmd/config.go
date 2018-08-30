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
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "show currnt config",
	Long:  `show currnt config.`,
	Run: func(cmd *cobra.Command, args []string) {
		const cfgTemplate = `[proxy]
pidfile = "{{ .proxy.pidfile }}"
useServerSterter = {{ .proxy.useserversterter }}
listenAddr = "{{ .proxy.listenaddr }}"
remoteAddr = "{{ .proxy.remoteaddr }}"
dumper = "{{ .proxy.dumper }}"

[log]
dir = "{{ .log.dir }}"
enable = "{{ .log.enable }}"
stdout = "{{ .log.stdout }}"
format = "{{ .log.format }}"
rotateEnable = {{ .log.rotateenable }}
rotationTime = "{{ .log.rotationtime }}"
rotationCount = {{ .log.rotationcount }}

[dumpLog]
dir = "{{ .dumplog.dir }}"
enable = "{{ .dumpLog.enable }}"
stdout = "{{ .dumpLog.stdout }}"
format = "{{ .dumplog.format }}"
rotateEnable = {{ .dumplog.rotateenable }}
rotationTime = "{{ .dumplog.rotationtime }}"
rotationCount = {{ .dumplog.rotationcount }}
`
		tpl, err := template.New("config").Parse(cfgTemplate)
		if err != nil {
			panic(err)
		}

		err = tpl.Execute(os.Stdout, viper.AllSettings())
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	configCmd.Flags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.AddCommand(configCmd)
}
