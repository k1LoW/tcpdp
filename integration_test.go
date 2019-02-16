// +build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	clean()
	code := m.Run()
	clean()
	os.Exit(code)
}

var proxyProtocolTests = []struct {
	description      string
	tcpdpCmd         string
	benchCmd         string
	benchMatchString string
}{
	{
		"haproxy[port:33068 send-proxy upstream:33080] -> tcpdp proxy -> mariadb[port:33081]",
		"./tcpdp proxy -l localhost:33080 -r localhost:33081 -d mysql --proxy-protocol --stdout",
		"mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=33068 --user=root --password=$MYSQL_ROOT_PASSWORD $MYSQL_DISABLE_SSL",
		"Number of clients running queries: 100",
	},
	{
		"haproxy[port:33069 send-proxy upstream:33081] -> mariadb[port:33081]",
		"sudo ./tcpdp probe -i $LO -t 33081 -d mysql -B 64MB --proxy-protocol --stdout",
		"mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=33069 --user=root --password=$MYSQL_ROOT_PASSWORD $MYSQL_DISABLE_SSL",
		"Number of clients running queries: 100",
	},
	{
		"haproxy[port:33070 send-proxy-v2 upstream:33080] -> tcpdp proxy -> mariadb[port:33081]",
		"./tcpdp proxy -l localhost:33080 -r localhost:33081 -d mysql --proxy-protocol --stdout",
		"mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=33070 --user=root --password=$MYSQL_ROOT_PASSWORD $MYSQL_DISABLE_SSL",
		"Number of clients running queries: 100",
	},
	{
		"haproxy[port:33071 send-proxy-v2 upstream:33081] -> mariadb[port:33081]",
		"sudo ./tcpdp probe -i $LO -t 33081 -d mysql -B 64MB --proxy-protocol --stdout",
		"mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=33071 --user=root --password=$MYSQL_ROOT_PASSWORD $MYSQL_DISABLE_SSL",
		"Number of clients running queries: 100",
	},
}

func TestProxyProtocol(t *testing.T) {
	for _, tt := range proxyProtocolTests {
		t.Run(tt.description, func(t *testing.T) {
			clean()
			ctx, cancel := context.WithCancel(context.Background())
			cmd := exec.CommandContext(ctx, "bash", "-c", tt.tcpdpCmd)
			stdout := new(bytes.Buffer)
			cmd.Stdout = stdout
			err := cmd.Start()
			if err != nil {
				cancel()
				t.Errorf("%v", err)
			}
			time.Sleep(1 * time.Second)
			out, err := exec.CommandContext(ctx, "bash", "-c", tt.benchCmd).CombinedOutput()
			if err != nil {
				cancel()
				t.Errorf("%v", err)
			}
			if !regexp.MustCompile(fmt.Sprintf("%s%s", `(?m)`, tt.benchMatchString)).Match(out) {
				t.Errorf("%s", "bench command failed")
			}
			results := regexp.MustCompile(`(?m)proxy_protocol_src_addr`).FindAllStringSubmatch(stdout.String(), -1)
			if len(results) < 100 {
				t.Errorf("%s:%s", "parse proxy protocol failed", stdout.String())
			}
			cancel()
		})
	}
}

func clean() {
	cmd := exec.Command("sudo", "rm", "-f", "tcpdp.log*", "dump.log*", "tcpdp.pid")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}
