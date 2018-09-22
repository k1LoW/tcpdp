# Changelog

## [v0.7.0](https://github.com/k1LoW/tcpdp/compare/v0.6.1...v0.7.0) (2018-09-23)

* [BREAKING]Parse PostgreSQL MessageParse / MessageBind / ( MessageExecute )  [#22](https://github.com/k1LoW/tcpdp/pull/22) ([k1LoW](https://github.com/k1LoW))
* Fix read StartupMessage [#21](https://github.com/k1LoW/tcpdp/pull/21) ([k1LoW](https://github.com/k1LoW))
* [BREAKING]Parse MySQL COM_STMT_PREPARE / COM_STMT_EXECUTE [#20](https://github.com/k1LoW/tcpdp/pull/20) ([k1LoW](https://github.com/k1LoW))
* Fix logic that read packet [#19](https://github.com/k1LoW/tcpdp/pull/19) ([k1LoW](https://github.com/k1LoW))

## [v0.6.1](https://github.com/k1LoW/tcpdp/compare/v0.6.0...v0.6.1) (2018-09-19)

* Remove pprof [#18](https://github.com/k1LoW/tcpdp/pull/18) ([k1LoW](https://github.com/k1LoW))
* Disable dump.log when execute `tcpdp read` [#17](https://github.com/k1LoW/tcpdp/pull/17) ([k1LoW](https://github.com/k1LoW))

## [v0.6.0](https://github.com/k1LoW/tcpdp/compare/v0.5.0...v0.6.0) (2018-09-19)

* Fix panic when exec root command with invalid option. [#16](https://github.com/k1LoW/tcpdp/pull/16) ([k1LoW](https://github.com/k1LoW))
* Add `read` command for read pcap file. [#15](https://github.com/k1LoW/tcpdp/pull/15) ([k1LoW](https://github.com/k1LoW))

## [v0.5.0](https://github.com/k1LoW/tcpdp/compare/v0.4.1...v0.5.0) (2018-09-14)

* `--target` can set port only [#13](https://github.com/k1LoW/tcpdp/pull/13) ([k1LoW](https://github.com/k1LoW))

## [v0.4.1](https://github.com/k1LoW/tcpdp/compare/v0.4.0...v0.4.1) (2018-09-14)

* Add `conn_id` to `probe` dump.log [#12](https://github.com/k1LoW/tcpdp/pull/12) ([k1LoW](https://github.com/k1LoW))
* Fix -d parse logic [#11](https://github.com/k1LoW/tcpdp/pull/11) ([k1LoW](https://github.com/k1LoW))

## [v0.4.0](https://github.com/k1LoW/tcpdp/compare/v0.3.0...v0.4.0) (2018-09-14)

* [BREAKING] Rename package `tcpdp` -> `tcpdp` [#10](https://github.com/k1LoW/tcpdp/pull/10) ([k1LoW](https://github.com/k1LoW))
* [BREAKING] Rename command `server` -> `proxy` [#9](https://github.com/k1LoW/tcpdp/pull/9) ([k1LoW](https://github.com/k1LoW))
* Add `probe` command like tcpdump [#8](https://github.com/k1LoW/tcpdp/pull/8) ([k1LoW](https://github.com/k1LoW))
* Refactor Dumper struct [#7](https://github.com/k1LoW/tcpdp/pull/7) ([k1LoW](https://github.com/k1LoW))

## [v0.3.0](https://github.com/k1LoW/tcprxy/compare/v0.2.1...v0.3.0) (2018-09-08)

* Analyze database name via Protocol::HandshakeResponse41 [#6](https://github.com/k1LoW/tcprxy/pull/6) ([k1LoW](https://github.com/k1LoW))

## [v0.2.1](https://github.com/k1LoW/tcprxy/compare/v0.2.0...v0.2.1) (2018-09-06)

* Fix `tcprxy config` output [#5](https://github.com/k1LoW/tcprxy/pull/5) ([k1LoW](https://github.com/k1LoW))

## [v0.2.0](https://github.com/k1LoW/tcprxy/compare/v0.1.0...v0.2.0) (2018-08-30)

* Add pidfile config [#4](https://github.com/k1LoW/tcprxy/pull/4) ([k1LoW](https://github.com/k1LoW))
* Add log config [#3](https://github.com/k1LoW/tcprxy/pull/3) ([k1LoW](https://github.com/k1LoW))
* Fix hex dump log config [#2](https://github.com/k1LoW/tcprxy/pull/2) ([k1LoW](https://github.com/k1LoW))

## [v0.1.0](https://github.com/k1LoW/tcprxy/compare/33d46026c86c...v0.1.0) (2018-08-29)

* Add dumper for MySQL query [#1](https://github.com/k1LoW/tcprxy/pull/1) ([k1LoW](https://github.com/k1LoW))
