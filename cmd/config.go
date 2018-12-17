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
	"fmt"
	"os"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show currnt config",
	Long:  `Show currnt config.`,
	Run: func(cmd *cobra.Command, args []string) {
		const cfgTemplate = `[tcpdp]
pidfile = "{{ .tcpdp.pidfile }}"
dumper = "{{ .tcpdp.dumper }}"

[probe]
interface = "{{ .probe.interface }}"
target = "{{ .probe.target }}"
bufferSize = "{{ .probe.buffersize }}"
immediateMode = {{ .probe.immediatemode }}
snapshotLength = "{{ .probe.snapshotlength }}"
internalBufferLength = {{ .probe.internalbufferlength }}
filter = "{{ .probe.filter }}"

[proxy]
useServerStarter = {{ .proxy.useserverstarter }}
listenAddr = "{{ .proxy.listenaddr }}"
remoteAddr = "{{ .proxy.remoteaddr }}"

[log]
dir = "{{ .log.dir }}"
enable = {{ .log.enable }}
stdout = {{ .log.stdout }}
format = "{{ .log.format }}"
rotateEnable = {{ .log.rotateenable }}
rotationTime = "{{ .log.rotationtime }}"
rotationCount = {{ .log.rotationcount }}
{{ if (ne .log.rotationhook "") -}}
rotationHook = "{{ .log.rotationhook }}"
fileName = "{{ .log.filename }}"
{{ else -}}
fileName = "{{ .log.filename }}"
{{- end }}

[dumpLog]
dir = "{{ .dumplog.dir }}"
enable = {{ .dumplog.enable }}
stdout = {{ .dumplog.stdout }}
format = "{{ .dumplog.format }}"
rotateEnable = {{ .dumplog.rotateenable }}
rotationTime = "{{ .dumplog.rotationtime }}"
rotationCount = {{ .dumplog.rotationcount }}
{{ if (ne .dumplog.rotationhook "") -}}
rotationHook = "{{ .dumplog.rotationhook }}"
fileName = "{{ .dumplog.filename }}"
{{ else -}}
fileName = "{{ .dumplog.filename }}"
{{- end -}}
`
		tpl, err := template.New("config").Parse(cfgTemplate)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := tpl.Execute(os.Stdout, viper.AllSettings()); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() {
	configCmd.Flags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.AddCommand(configCmd)
}
