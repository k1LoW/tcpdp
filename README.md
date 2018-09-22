# tcpdp [![Build Status](https://travis-ci.org/k1LoW/tcpdp.svg?branch=master)](https://travis-ci.org/k1LoW/tcpdp) [![GitHub release](https://img.shields.io/github/release/k1LoW/tcpdp.svg)](https://github.com/k1LoW/tcpdp/releases)

tcpdp is TCP dump tool with custom dumper written in Go.

## Usage

### `tcpdp proxy` : TCP proxy server mode

``` console
$ tcpdp proxy -l localhost:12345 -r localhost:1234 -d hex # hex.Dump()
```

``` console
$ tcpdp proxy -l localhost:55432 -r localhost:5432 -d pg # Dump query of PostgreSQL
```

``` console
$ tcpdp proxy -l localhost:33306 -r localhost:3306 -d mysql # Dump query of MySQL
```

#### With server-starter

https://github.com/lestrrat-go/server-starter

``` console
$ start_server --port 33306 -- tcpdp proxy -s -r localhost:3306 -d mysql
```

#### With config file

``` console
$ tcpdp proxy -c config.toml
```

### `tcpdp probe` : Probe mode (like tcpdump)

``` console
$ tcpdp probe -i lo0 -t localhost:3306 -d mysql # is almost the same setting as 'tcpdump -i lo0 host 127.0.0.1 and tcp port 3306'
```

``` console
$ tcpdp probe -i eth0 -t 3306 -d hex # is almost the same setting as 'tcpdump -i eth0 tcp port 3306'
```

### `tcpdp read` : Read pcap file mode

``` console
$ tcpdump -i eth0 host 127.0.0.1 and tcp port 3306 -w mysql.pcap
$ tcpdp read mysql.pcap -d mysql -f ltsv
```

### `tcpdp config` Create config

``` console
$ tcpdp config > myconfig.toml
```

#### Show current config

``` console
$ tcpdp config
```

#### config format

``` toml
[tcpdp]
pidfile = "/var/run/tcpdp.pid"
dumper = "mysql"

[probe]
target = "db.example.com:3306"
interface = "en0"

[proxy]
useServerSterter = false
listenAddr = "localhost:3306"
remoteAddr = "db.example.com:3306"

[log]
dir = "/var/log/tcpdp"
enable = true
stdout = true
format = "ltsv"
rotateEnable = true
rotationTime = "daily"
rotationCount = 7

[dumpLog]
dir = "/var/log/dump"
enable = true
stdout = false
format = "json"
rotateEnable = true
rotationTime = "hourly"
rotationCount = 24
```

## Installation

```console
$ go get github.com/k1LoW/tcpdp
```

## Architecture

### tcpdp proxy connection diagram

```
      client_addr
           ^
           |        tcpdp
+----------|---------------+
|          v               |
|  proxy_listen_addr       |
|         + ^              |
|         | |   +--------+ |
|         |<----+ dumper | |
|         | |<--+        | |
|         | |   +--------+ |
|         v +              |
|  proxy_client_addr       |
|          ^               |
+----------|---------------+
           |
           v
      remote_addr
```

### tcpdp probe connection diagram

```
                    server
+--------------------------+
|                          |
|                      +---+---+
|       <--------------| eth0  |----------->
|            interface +---+---+
|            /target     ^ |
|                        | |
|         tcpdp          | |
|        +--------+      | |
|        | dumper +------+ |
|        +--------+        |
+--------------------------+
```

## Log keys

| key | description | tcpdp.log / dump.log (dumper type) | mode |
| --- | ----------- | ---------------------------------- | ---- |
| ts | timestamp | tcpdp.log, hex, mysql, pg | proxy / probe / read |
| level | log level | tcpdp.log | proxy / probe |
| msg | log message | tcpdp.log | proxy / probe |
| error | error info | tcpdp.log | proxy / probe |
| caller | error caller | tcpdp.log | proxy / probe |
| conn_id | TCP connection ID by tcpdp | tcpdp.log, hex, mysql, pg | proxy / probe / read |
| conn_seq_num | TCP comunication sequence number by tcpdp | tcpdp.log, hex, mysql, pg | proxy |
| client_addr | client address | tcpdp.log, hex, mysql, pg | proxy |
| proxy_listen_addr | listen address| tcpdp.log, hex, mysql, pg | proxy |
| proxy_client_addr | proxy client address | hex, mysql, pg | proxy |
| remote_addr | remote address | tcpdp.log, hex, mysql, pg | proxy |
| direction | client to remote: `->` / remote to client: `<-` | tcpdp.log, hex, mysql, pg | proxy |
| interface | probe target interface | tcpdp.log, hex, mysql, pg | probe |
| src_addr | src address | tcpdp.log, hex, mysql, pg | probe / read |
| dst_addr | dst address | tcpdp.log, hex, mysql, pg | probe / read |
| probe_target_addr | probe target address | tcpdp.log, hex, mysql, pg | probe |
| dump | dump data by hex.Dump | hex | proxy / probe / read |
| query | SQL query | mysql, pg | proxy / probe / read |
| stmt_id | statement id | mysql | proxy / probe / read |
| stmt_prepare_query | prepared statement query | mysql | proxy / probe / read |
| stmt_execute_values | prepared statement execute values | mysql | proxy / probe / read |
| portal_name | portal Name | pg | proxy / probe / read |
| stmt_name | prepared statement name | pg | proxy / probe / read |
| parse_query | prepared statement query | pg | proxy / probe / read |
| bind_values | prepared statement bind(execute) values | pg | proxy / probe / read |
| username | username | mysql, pg | proxy / probe / read |
| database | database | mysql, pg | proxy / probe / read |
| seq_num | sequence number by MySQL | mysql | proxy / probe / read |
| command_id | [command_id](https://dev.mysql.com/doc/internals/en/com-query.html) for MySQL | mysql | proxy / probe / read |
| message_type | [message type](https://www.postgresql.org/docs/current/static/protocol-overview.html#PROTOCOL-MESSAGE-CONCEPTS) for PostgreSQL | pg | proxy / probe / read |

## References

- https://github.com/jpillora/go-tcp-proxy
- https://github.com/dmmlabo/tcpserver_go
