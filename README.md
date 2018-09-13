# tcpdp

tcpdp is TCP dump tool with custom dumper written in Go.

## Usage

### `tcpdp proxy`

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

### `tcpdp probe`

``` console
$ tcpdp probe -i lo0 -t localhost:3306 -d mysql
```

### Create config

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

## tcpdp connection diagram

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

## log

| key | description | tcpdp.log / dump.log (dumper type) |
| --- | ----------- | ----------------------------------- |
| ts | timestamp | tcpdp.log, hex, mysql, pg |
| level | log level | tcpdp.log |
| msg | log message | tcpdp.log |
| error | error info | tcpdp.log |
| caller | error caller | tcpdp.log |
| conn_id | TCP connection ID by tcpdp | tcpdp.log, hex, mysql, pg |
| conn_seq_num | TCP comunication sequence number by tcpdp | tcpdp.log, hex, mysql, pg |
| client_addr | client address | tcpdp.log, hex, mysql, pg |
| proxy_listen_addr | listen address| tcpdp.log, hex, mysql, pg |
| proxy_client_addr | proxy client address | hex, mysql, pg |
| remote_addr | remote address | tcpdp.log, hex, mysql, pg |
| direction | client to remote: `->` / remote to client: `<-` | tcpdp.log, hex, mysql, pg |
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
