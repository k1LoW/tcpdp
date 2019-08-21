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
	"runtime"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	clean()
	code := m.Run()
	clean()
	os.Exit(code)
}

var proxyTests = []struct {
	description      string
	tcpdpCmd         string
	benchCmd         string
	benchMatchString string
}{
	{
		"tcpdp proxy -> postgresql",
		"./tcpdp proxy -l localhost:54321 -r localhost:$POSTGRES_PORT -d pg --stdout",
		"PGPASSWORD=$POSTGRES_PASSWORD pgbench -i postgresql://$POSTGRES_USER@127.0.0.1:54321/$POSTGRES_DB?sslmode=disable && PGPASSWORD=$POSTGRES_PASSWORD pgbench -c 100 -t 10 postgresql://$POSTGRES_USER@127.0.0.1:54321/$POSTGRES_DB?sslmode=disable",
		"number of transactions actually processed: 1000/1000",
	},
	{
		"tcpdp proxy -> mysql",
		"./tcpdp proxy -l localhost:33065 -r localhost:$MYSQL_PORT -d mysql --stdout",
		"mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=33065 --user=root --password=$MYSQL_ROOT_PASSWORD $MYSQL_DISABLE_SSL",
		"Number of clients running queries: 100",
	},
}

func TestProxy(t *testing.T) {
	for _, tt := range proxyTests {
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
				t.Errorf("%v:%s", err, out)
			}
			if !regexp.MustCompile(fmt.Sprintf("%s%s", `(?m)`, tt.benchMatchString)).Match(out) {
				t.Errorf("%s", "bench command failed")
			}
			results := regexp.MustCompile(`(?m)proxy_listen_addr`).FindAllStringSubmatch(stdout.String(), -1)
			if len(results) < 100 {
				t.Errorf("%s:%s", "parse protocol failed", stdout.String())
			}
			cancel()
		})
	}
}

var probeTests = []struct {
	description      string
	tcpdpCmd         string
	benchCmd         string
	benchMatchString string
	linuxOnly        bool
}{
	{
		"tcpdp probe - lo -> postgresql",
		"sudo ./tcpdp probe -i $LO -t $POSTGRES_PORT -d pg -B 64MB --stdout",
		"PGPASSWORD=$POSTGRES_PASSWORD pgbench -i postgresql://$POSTGRES_USER@127.0.0.1:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable && PGPASSWORD=$POSTGRES_PASSWORD pgbench -c 100 -t 10 postgresql://$POSTGRES_USER@127.0.0.1:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable",
		"number of transactions actually processed: 1000/1000",
		false,
	},
	{
		"tcpdp probe - lo -> mysql",
		"sudo ./tcpdp probe -i $LO -t $MYSQL_PORT -d mysql -B 64MB --stdout",
		"mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=$MYSQL_PORT --user=root --password=$MYSQL_ROOT_PASSWORD $MYSQL_DISABLE_SSL",
		"Number of clients running queries: 100",
		false,
	},
	{
		"tcpdp probe - any -> postgresql",
		"sudo ./tcpdp probe -i any -t $POSTGRES_PORT -d pg -B 64MB --stdout",
		"PGPASSWORD=$POSTGRES_PASSWORD pgbench -i postgresql://$POSTGRES_USER@127.0.0.1:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable && PGPASSWORD=$POSTGRES_PASSWORD pgbench -c 100 -t 10 postgresql://$POSTGRES_USER@127.0.0.1:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable",
		"number of transactions actually processed: 1000/1000",
		true,
	},
	{
		"tcpdp probe - any -> mysql",
		"sudo ./tcpdp probe -i any -t $MYSQL_PORT -d mysql -B 64MB --stdout",
		"mysqlslap --no-defaults --concurrency=100 --iterations=1 --auto-generate-sql --auto-generate-sql-add-autoincrement --auto-generate-sql-load-type=mixed --auto-generate-sql-write-number=100 --number-of-queries=1000 --host=127.0.0.1 --port=$MYSQL_PORT --user=root --password=$MYSQL_ROOT_PASSWORD $MYSQL_DISABLE_SSL",
		"Number of clients running queries: 100",
		true,
	},
}

func TestProbe(t *testing.T) {
	for _, tt := range probeTests {
		if tt.linuxOnly && runtime.GOOS != "linux" {
			t.Skip()
		}

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
				t.Errorf("%v:%s", err, out)
			}
			if !regexp.MustCompile(fmt.Sprintf("%s%s", `(?m)`, tt.benchMatchString)).Match(out) {
				t.Errorf("%s", "bench command failed")
			}
			results := regexp.MustCompile(`(?m)probe_target_addr`).FindAllStringSubmatch(stdout.String(), -1)
			if len(results) < 100 {
				t.Errorf("%s:%s", "parse protocol failed", stdout.String())
			}
			cancel()
		})
	}
}

var readTests = []struct {
	description string
	tcpdpCmd    string
}{
	{
		"tcpdp read pg_prepare.pcap",
		"./tcpdp read -t $POSTGRES_PORT -d pg ./testdata/pcap/pg_prepare.pcap",
	},
	{
		"tcpdp read mysql_prepare.pcap",
		"./tcpdp read -t $MYSQL_PORT -d mysql ./testdata/pcap/mysql_prepare.pcap",
	},
}

func TestRead(t *testing.T) {
	for _, tt := range readTests {
		t.Run(tt.description, func(t *testing.T) {
			clean()
			cmd := exec.Command("bash", "-c", tt.tcpdpCmd)
			cmd.Env = os.Environ()
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("%v:%s", err, out)
			}
			results := regexp.MustCompile(`(?m)query`).FindAllStringSubmatch(string(out), -1)
			if len(results) < 10 {
				t.Errorf("%s:%s", "parse protocol failed", string(out))
			}
		})
	}
}

var longQueryTests = []struct {
	description string
	tcpdpCmd    string
	benchCmd    string
}{
	{
		"tcpdp proxy mysql long query",
		"./tcpdp proxy -l localhost:33065 -r localhost:$MYSQL_PORT -d mysql --stdout",
		"mysql --host=127.0.0.1 --port=33065 --user=root --password=$MYSQL_ROOT_PASSWORD testdb $MYSQL_DISABLE_SSL < ./testdata/query/long.sql 2>&1 > /dev/null",
	},
	{
		"tcpdp probe mysql long query",
		"sudo ./tcpdp probe -i $LO -t $MYSQL_PORT -d mysql -B 64MB --stdout",
		"mysql --host=127.0.0.1 --port=$MYSQL_PORT --user=root --password=$MYSQL_ROOT_PASSWORD testdb $MYSQL_DISABLE_SSL < ./testdata/query/long.sql 2>&1 > /dev/null",
	},
	{
		"tcpdp proxy postgresql long query",
		"./tcpdp proxy -l localhost:54321 -r localhost:$POSTGRES_PORT -d pg --stdout",
		"PGPASSWORD=$POSTGRES_PASSWORD psql postgresql://$POSTGRES_USER@127.0.0.1:54321/$POSTGRES_DB?sslmode=disable < ./testdata/query/long.sql 2>&1 > /dev/null",
	},
	{
		"tcpdp probe postgresql long query",
		"sudo ./tcpdp probe -i $LO -t $POSTGRES_PORT -d pg -B 64MB --stdout",
		"PGPASSWORD=$POSTGRES_PASSWORD psql postgresql://$POSTGRES_USER@127.0.0.1:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable < ./testdata/query/long.sql 2>&1 > /dev/null",
	},
}

func TestLongQuery(t *testing.T) {
	for _, tt := range longQueryTests {
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
			err = exec.CommandContext(ctx, "bash", "-c", tt.benchCmd).Run()
			if err != nil {
				cancel()
				t.Errorf("%v", err)
			}
			time.Sleep(1 * time.Second)
			if !regexp.MustCompile(`(?m)query_start`).MatchString(stdout.String()) {
				t.Errorf("%s:%s", "parse long query failed", stdout.String())
			}
			if !regexp.MustCompile(`(?m)query_last`).MatchString(stdout.String()) {
				t.Errorf("%s:%s", "parse long query failed", stdout.String())
			}
			cancel()
		})
	}
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
			if stdout.String() != "" {
				t.Fatalf("%s:%s", "stdout not empty", stdout.String())
			}
			err := cmd.Start()
			if err != nil {
				cancel()
				t.Errorf("%v", err)
			}
			time.Sleep(1 * time.Second)
			out, err := exec.CommandContext(ctx, "bash", "-c", tt.benchCmd).CombinedOutput()
			if err != nil {
				cancel()
				t.Errorf("%v:%s", err, out)
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

var connTests = []struct {
	description      string
	tcpdpCmd         string
	benchCmd         string
	benchMatchString string
}{
	{
		"tcpdp probe - lo -> postgresql",
		"sudo ./tcpdp probe -i $LO -t $POSTGRES_PORT -d conn -B 64MB --stdout",
		"PGPASSWORD=$POSTGRES_PASSWORD pgbench -i postgresql://$POSTGRES_USER@127.0.0.1:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable && PGPASSWORD=$POSTGRES_PASSWORD pgbench -c 100 -t 10 postgresql://$POSTGRES_USER@127.0.0.1:$POSTGRES_PORT/$POSTGRES_DB?sslmode=disable",
		"number of transactions actually processed: 1000/1000",
	},
}

func TestConn(t *testing.T) {
	for _, tt := range connTests {
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
				t.Errorf("%v:%s", err, out)
			}
			if !regexp.MustCompile(fmt.Sprintf("%s%s", `(?m)`, tt.benchMatchString)).Match(out) {
				t.Errorf("%s", "bench command failed")
			}
			results := regexp.MustCompile(`(?m)conn_id`).FindAllStringSubmatch(stdout.String(), -1)
			if len(results) < 100 {
				t.Errorf("%s:%s", "track connection failed", stdout.String())
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
