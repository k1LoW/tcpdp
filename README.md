# tcpdp [![Build Status](https://travis-ci.org/k1LoW/tcpdp.svg?branch=master)](https://travis-ci.org/k1LoW/tcpdp) [![GitHub release](https://img.shields.io/github/release/k1LoW/tcpdp.svg)](https://github.com/k1LoW/tcpdp/releases)

tcpdp is TCP dump tool with custom dumper written in Go.

## Usage

### `tcpdp proxy` : TCP proxy server mode

``` console
$ tcpdp proxy -l localhost:12345 -r localhost:1234 -d hex # hex.Dump()
```

``` console
$ tcpdp proxy -l localhost:55432 -r db.internal.example.com:5432 -d pg # Dump query of PostgreSQL
```

``` console
$ tcpdp proxy -l localhost:33306 -r db.example.com:3306 -d mysql # Dump query of MySQL
```

#### With server-starter

https://github.com/lestrrat-go/server-starter

``` console
$ start_server --port 33306 -- tcpdp proxy -s -r db.example.com:3306 -d mysql
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
$ tcpdp read mysql.pcap -d mysql -t 3306 -f ltsv
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
bufferSize = "2MB"
immediateMode = false

[proxy]
useServerStarter = false
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
# You can execute arbitrary commands after rotate
# $1 = prev filename
# $2 = current filename
rotationHook = "/path/to/after_rotate.sh"

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

### tcpdp read diagram

```
                  tcpdp
+--------+ STDIN +--------+ STDOUT
| *.pcap +------>+ dumper +-------->
+--------+       +--------+
```

## tcpdp.log ( `tcpdp proxy` or `tcpdp probe` )

| key | description | mode |
| --- | ----------- | ---- |
| ts | timestamp | proxy / probe / read |
| level | log level | proxy / probe |
| msg | log message | proxy / probe |
| error | error info | proxy / probe |
| caller | error caller | proxy / probe |
| conn_id | TCP connection ID by tcpdp | proxy / probe |
| conn_seq_num | TCP comunication sequence number by tcpdp | proxy |
| client_addr | client address | tcpdp.log, hex, mysql, pg | proxy |
| proxy_listen_addr | listen address| proxy |
| direction | client to remote: `->` / remote to client: `<-` | proxy |
| interface | probe target interface | probe |
| probe_target_addr | probe target address | probe |

## Dumper

### mysql

MySQL query dumper

**NOTICE: MySQL query dumper require `--target` option when `tcpdp proxy` `tcpdp probe`**

| key | description | mode |
| --- | ----------- | ---- |
| ts | timestamp | proxy / probe / read |
| conn_id | TCP connection ID by tcpdp | proxy / probe / read |
| conn_seq_num | TCP comunication sequence number by tcpdp | proxy |
| client_addr | client address | proxy |
| proxy_listen_addr | listen address| proxy |
| proxy_client_addr | proxy client address | proxy |
| remote_addr | remote address | proxy |
| direction | client to remote: `->` / remote to client: `<-` | proxy |
| interface | probe target interface | probe |
| src_addr | src address | probe / read |
| dst_addr | dst address | probe / read |
| probe_target_addr | probe target address | probe |
| query | SQL query | proxy / probe / read |
| stmt_id | statement id | proxy / probe / read |
| stmt_prepare_query | prepared statement query | proxy / probe / read |
| stmt_execute_values | prepared statement execute values | proxy / probe / read |
| character_set | [character set](https://dev.mysql.com/doc/internals/en/character-set.html) | proxy / probe / read |
| username | username | proxy / probe / read |
| database | database | proxy / probe / read |
| seq_num | sequence number by MySQL | proxy / probe / read |
| command_id | [command_id](https://dev.mysql.com/doc/internals/en/com-query.html) for MySQL | proxy / probe / read |

### pg

PostgreSQL query dumper

**NOTICE: PostgreSQL query dumper require `--target` option `tcpdp proxy` `tcpdp probe`**

| key | description | mode |
| --- | ----------- | ---- |
| ts | timestamp | proxy / probe / read |
| conn_id | TCP connection ID by tcpdp | proxy / probe / read |
| conn_seq_num | TCP comunication sequence number by tcpdp | proxy |
| client_addr | client address | proxy |
| proxy_listen_addr | listen address| proxy |
| proxy_client_addr | proxy client address | proxy |
| remote_addr | remote address | proxy |
| direction | client to remote: `->` / remote to client: `<-` | proxy |
| interface | probe target interface | probe |
| src_addr | src address | probe / read |
| dst_addr | dst address | probe / read |
| probe_target_addr | probe target address | probe |
| query | SQL query | proxy / probe / read |
| portal_name | portal Name | proxy / probe / read |
| stmt_name | prepared statement name | proxy / probe / read |
| parse_query | prepared statement query | proxy / probe / read |
| bind_values | prepared statement bind(execute) values | proxy / probe / read |
| username | username | proxy / probe / read |
| database | database | proxy / probe / read |
| message_type | [message type](https://www.postgresql.org/docs/current/static/protocol-overview.html#PROTOCOL-MESSAGE-CONCEPTS) for PostgreSQL | proxy / probe / read |

### hex

| key | description | mode |
| --- | ----------- | ---- |
| ts | timestamp | proxy / probe / read |
| conn_id | TCP connection ID by tcpdp | proxy / probe / read |
| conn_seq_num | TCP comunication sequence number by tcpdp | proxy |
| client_addr | client address | proxy |
| proxy_listen_addr | listen address| proxy |
| proxy_client_addr | proxy client address | proxy |
| remote_addr | remote address | proxy |
| direction | client to remote: `->` / remote to client: `<-` | proxy |
| interface | probe target interface | probe |
| src_addr | src address | probe / read |
| dst_addr | dst address | probe / read |
| probe_target_addr | probe target address | probe |
| bytes | bytes string by hex.Dump | proxy / probe / read |
| ascii | ascii string by hex.Dump | proxy / probe / read |

## References

- https://github.com/jpillora/go-tcp-proxy
- https://github.com/dmmlabo/tcpserver_go
