# tcprxy

tcprxy is TCP proxy with custom dumper written in Go.

## Usage

``` console
$ tcprxy server -l localhost:12345 -r localhost:1234 -d hex # hex.Dump()
```

``` console
$ tcprxy server -l localhost:55432 -r localhost:5432 -d pg # Dump query of PostgreSQL
```

``` console
$ tcprxy server -l localhost:33306 -r localhost:3306 -d mysql # Dump query of MySQL
```

### With server-starter

https://github.com/lestrrat-go/server-starter

``` console
$ start_server --port 33306 -- tcprxy server -s -r localhost:3306 -d mysql
```

### With config file

``` console
$ tcprxy server -c config.toml
```

#### Create config

``` console
$ tcprxy config > myconfig.toml
```

#### Show current config

``` console
$ tcprxy config
```

#### config format

``` toml
[proxy]
pidfile = "/var/run/tcprxy.pid"
useServerSterter = false
listenAddr = "localhost:3306"
remoteAddr = "db.example.com:3306"
dumper = "mysql"

[log]
dir = "/var/log/tcprxy"
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

## tcprxy connection diagram

```
      client_addr
           ^
           |        tcprxy
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

## log

| key | description | tcprxy.log / dump.log (dumper type) |
| --- | ----------- | ----------------------------------- |
| ts | timestamp | tcprxy.log, hex, mysql, pg |
| level | log level | tcprxy.log |
| msg | log message | tcprxy.log |
| error | error info | tcprxy.log |
| caller | error caller | tcprxy.log |
| conn_id | TCP connection ID by tcprxy | tcprxy.log, hex, mysql, pg |
| conn_seq_num | TCP comunication sequence number by tcprxy | tcprxy.log, hex, mysql, pg |
| client_addr | client address | tcprxy.log, hex, mysql, pg |
| proxy_listen_addr | listen address| tcprxy.log, hex, mysql, pg |
| proxy_client_addr | proxy client address | hex, mysql, pg |
| remote_addr | remote address | tcprxy.log, hex, mysql, pg |
| direction | client to remote: `->` / remote to client: `<-` | tcprxy.log, hex, mysql, pg |
| dump | dump data by hex.Dump | hex |
| query | SQL query | mysql, pg |
| username | username | mysql, pg |
| database | database | mysql, pg |
| seq_num | sequence number by MySQL | mysql |
| command_id | [command_id](https://dev.mysql.com/doc/internals/en/com-query.html) for MySQL | mysql |
| message_type | [message type](https://www.postgresql.org/docs/current/static/protocol-overview.html#PROTOCOL-MESSAGE-CONCEPTS) for PostgreSQL | pg |

## References

- https://github.com/jpillora/go-tcp-proxy
- https://github.com/dmmlabo/tcpserver_go
