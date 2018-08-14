# [WIP] tcprxy

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

## References

- https://github.com/jpillora/go-tcp-proxy
- https://github.com/dmmlabo/tcpserver_go
