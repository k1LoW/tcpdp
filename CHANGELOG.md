# Changelog

## [v0.22.1](https://github.com/k1LoW/tcpdp/compare/v0.22.0...v0.22.1) (2021-09-07)

* Fix null pointer dereference [#96](https://github.com/k1LoW/tcpdp/pull/96) ([k1LoW](https://github.com/k1LoW))

## [v0.22.0](https://github.com/k1LoW/tcpdp/compare/v0.21.1...v0.22.0) (2020-11-25)

* Fix payloadBuffer invalid nil pointer dereference [#95](https://github.com/k1LoW/tcpdp/pull/95) ([k1LoW](https://github.com/k1LoW))
* Use GitHub Actions [#94](https://github.com/k1LoW/tcpdp/pull/94) ([k1LoW](https://github.com/k1LoW))
* Bump up go version [#93](https://github.com/k1LoW/tcpdp/pull/93) ([k1LoW](https://github.com/k1LoW))
* fix a typo in doc string [#92](https://github.com/k1LoW/tcpdp/pull/92) ([kentaro](https://github.com/kentaro))
* Fix payloadBuffer.Get ( when buffer deleted, return nil ) [#91](https://github.com/k1LoW/tcpdp/pull/91) ([k1LoW](https://github.com/k1LoW))
* Add make sec [#89](https://github.com/k1LoW/tcpdp/pull/89) ([k1LoW](https://github.com/k1LoW))

## [v0.21.2](https://github.com/k1LoW/tcpdp/compare/v0.21.1...v0.21.2) (2019-08-09)

* Fix payloadBuffer.Get ( when buffer deleted, return nil ) [#91](https://github.com/k1LoW/tcpdp/pull/91) ([k1LoW](https://github.com/k1LoW))
* Add make sec [#89](https://github.com/k1LoW/tcpdp/pull/89) ([k1LoW](https://github.com/k1LoW))

## [v0.21.0](https://github.com/k1LoW/tcpdp/compare/v0.20.3...v0.21.0) (2019-06-19)

* Add lock/unlock to the place to operate pMap.buffers [#88](https://github.com/k1LoW/tcpdp/pull/88) ([k1LoW](https://github.com/k1LoW))
* Log *addr when dumper.Read error ( ex. SSL connection ) [#86](https://github.com/k1LoW/tcpdp/pull/86) ([k1LoW](https://github.com/k1LoW))

## [v0.20.3](https://github.com/k1LoW/tcpdp/compare/v0.20.2...v0.20.3) (2019-06-11)

* Add more memStats metrics [#85](https://github.com/k1LoW/tcpdp/pull/85) ([k1LoW](https://github.com/k1LoW))
* handle FIN / RST to delete unused buffer [#84](https://github.com/k1LoW/tcpdp/pull/84) ([k1LoW](https://github.com/k1LoW))
* Add mutex to payloadBufferManager [#83](https://github.com/k1LoW/tcpdp/pull/83) ([k1LoW](https://github.com/k1LoW))
* hundle dumper.Read error and delete unnecessary buffer [#82](https://github.com/k1LoW/tcpdp/pull/82) ([k1LoW](https://github.com/k1LoW))

## [v0.20.2](https://github.com/k1LoW/tcpdp/compare/v0.20.1...v0.20.2) (2019-06-09)

* Fix payload buffer leak [#81](https://github.com/k1LoW/tcpdp/pull/81) ([k1LoW](https://github.com/k1LoW))

## [v0.20.1](https://github.com/k1LoW/tcpdp/compare/v0.20.0...v0.20.1) (2019-06-06)

* Fix output `tcpdp version`

## [v0.20.0](https://github.com/k1LoW/tcpdp/compare/v0.19.0...v0.20.0) (2019-06-04)

* Add `log.enableInternal` to log tcpdp internal stats [#80](https://github.com/k1LoW/tcpdp/pull/80) ([k1LoW](https://github.com/k1LoW))

## [v0.19.0](https://github.com/k1LoW/tcpdp/compare/v0.18.0...v0.19.0) (2019-05-15)

* Add dumper `conn` for tracking only connection [#79](https://github.com/k1LoW/tcpdp/pull/79) ([k1LoW](https://github.com/k1LoW))

## [v0.18.0](https://github.com/k1LoW/tcpdp/compare/v0.17.0...v0.18.0) (2019-05-14)

* Build using Go 1.12.x [#78](https://github.com/k1LoW/tcpdp/pull/78) ([k1LoW](https://github.com/k1LoW))
* Support `-i any` (Linux only) [#77](https://github.com/k1LoW/tcpdp/pull/77) ([k1LoW](https://github.com/k1LoW))

## [v0.17.0](https://github.com/k1LoW/tcpdp/compare/v0.16.1...v0.17.0) (2019-02-17)

* Gonize integration test [#76](https://github.com/k1LoW/tcpdp/pull/76) ([k1LoW](https://github.com/k1LoW))
* Support proxy protocol [#75](https://github.com/k1LoW/tcpdp/pull/75) ([k1LoW](https://github.com/k1LoW))

## [v0.16.1](https://github.com/k1LoW/tcpdp/compare/v0.16.0...v0.16.1) (2018-12-17)

* Refactor NewProbeServer and logging info [#74](https://github.com/k1LoW/tcpdp/pull/74) ([k1LoW](https://github.com/k1LoW))

## [v0.16.0](https://github.com/k1LoW/tcpdp/compare/v0.15.0...v0.16.0) (2018-12-16)

* Add `--filter` option for override BPF [#73](https://github.com/k1LoW/tcpdp/pull/73) ([k1LoW](https://github.com/k1LoW))
* Support multi target [#72](https://github.com/k1LoW/tcpdp/pull/72) ([k1LoW](https://github.com/k1LoW))

## [v0.15.0](https://github.com/k1LoW/tcpdp/compare/v0.14.1...v0.15.0) (2018-12-12)

* Add `--stdout` option [#71](https://github.com/k1LoW/tcpdp/pull/71) ([k1LoW](https://github.com/k1LoW))

## [v0.14.1](https://github.com/k1LoW/tcpdp/compare/v0.14.0...v0.14.1) (2018-12-07)

* Fix COM_STMT_EXECUTE with zero stmt_execute_values [#70](https://github.com/k1LoW/tcpdp/pull/70) ([k1LoW](https://github.com/k1LoW))
* Fix break packets for parsing HandshakeResponse320 [#69](https://github.com/k1LoW/tcpdp/pull/69) ([k1LoW](https://github.com/k1LoW))

## [v0.14.0](https://github.com/k1LoW/tcpdp/compare/v0.13.1...v0.14.0) (2018-11-28)

* Add Unsupport SSL warning when Protocol::HandshakeResponse320 [#68](https://github.com/k1LoW/tcpdp/pull/68) ([k1LoW](https://github.com/k1LoW))
* Analyze username and database name via Protocol::HandshakeResponse320 [#67](https://github.com/k1LoW/tcpdp/pull/67) ([k1LoW](https://github.com/k1LoW))
* Check SSLRequest when parsing Handshake and write warning to dump.log [#66](https://github.com/k1LoW/tcpdp/pull/66) ([k1LoW](https://github.com/k1LoW))

## [v0.13.1](https://github.com/k1LoW/tcpdp/compare/v0.13.0...v0.13.1) (2018-10-23)

* Write `mtu` `mss` to log [#65](https://github.com/k1LoW/tcpdp/pull/65) ([k1LoW](https://github.com/k1LoW))
* Fix default snapshotLength and Fix auto detect snapshotLength [#64](https://github.com/k1LoW/tcpdp/pull/64) ([k1LoW](https://github.com/k1LoW))

## [v0.13.0](https://github.com/k1LoW/tcpdp/compare/v0.12.0...v0.13.0) (2018-10-22)

* Add `--snapshot-length` option to `tcpdp probe` [#63](https://github.com/k1LoW/tcpdp/pull/63) ([k1LoW](https://github.com/k1LoW))
* Check clientSSL when parsing HandshakeResponse and write warning to dump.log [#62](https://github.com/k1LoW/tcpdp/pull/62) ([k1LoW](https://github.com/k1LoW))
* Add *log.fileName config option [#61](https://github.com/k1LoW/tcpdp/pull/61) ([k1LoW](https://github.com/k1LoW))

## [v0.12.0](https://github.com/k1LoW/tcpdp/compare/v0.11.0...v0.12.0) (2018-10-14)

* Make internal packet buffer [#57](https://github.com/k1LoW/tcpdp/pull/57) ([k1LoW](https://github.com/k1LoW))
* Add `make lint` [#60](https://github.com/k1LoW/tcpdp/pull/60) ([k1LoW](https://github.com/k1LoW))
* Support PostgreSQL long query [#59](https://github.com/k1LoW/tcpdp/pull/59) ([k1LoW](https://github.com/k1LoW))
* Fix probe / proxy starting log format [#56](https://github.com/k1LoW/tcpdp/pull/56) ([k1LoW](https://github.com/k1LoW))
* Fix `--use-server-starter` option ( replace miss ) [#55](https://github.com/k1LoW/tcpdp/pull/55) ([k1LoW](https://github.com/k1LoW))
* Disable promiscuous mode [#54](https://github.com/k1LoW/tcpdp/pull/54) ([k1LoW](https://github.com/k1LoW))
* Add rotationTime `secondly` [#51](https://github.com/k1LoW/tcpdp/pull/51) [#53](https://github.com/k1LoW/tcpdp/pull/53) ([k1LoW](https://github.com/k1LoW))

## [v0.11.0](https://github.com/k1LoW/tcpdp/compare/v0.10.0...v0.11.0) (2018-10-10)

* Add `--immediate-mode` option to `tcpdp probe` [#50](https://github.com/k1LoW/tcpdp/pull/50) ([k1LoW](https://github.com/k1LoW))
* Add `--buffer-size (-B)` option to `tcpdp probe` [#49](https://github.com/k1LoW/tcpdp/pull/49) ([k1LoW](https://github.com/k1LoW))
* Log pcap_stats when shutdown probe server or packets dropped [#48](https://github.com/k1LoW/tcpdp/pull/48) ([k1LoW](https://github.com/k1LoW))
* Increase snaplen so as not to lost packets [#47](https://github.com/k1LoW/tcpdp/pull/47) ([k1LoW](https://github.com/k1LoW))
* Add logger to PacketReader [#46](https://github.com/k1LoW/tcpdp/pull/46) ([k1LoW](https://github.com/k1LoW))
* bMap should be per direction ( not per connection ) [#45](https://github.com/k1LoW/tcpdp/pull/45) ([k1LoW](https://github.com/k1LoW))
* Support MySQL long query with payload_length [#44](https://github.com/k1LoW/tcpdp/pull/44) ([k1LoW](https://github.com/k1LoW))
* Support long packet [#43](https://github.com/k1LoW/tcpdp/pull/43) ([k1LoW](https://github.com/k1LoW))
* update ghch [#42](https://github.com/k1LoW/tcpdp/pull/42) ([pyama86](https://github.com/pyama86))

## [v0.10.0](https://github.com/k1LoW/tcpdp/compare/v0.9.1...v0.10.0) (2018-09-30)

* Build deb package [#39](https://github.com/k1LoW/tcpdp/pull/39) ([k1LoW](https://github.com/k1LoW))
* Build RPM package [#38](https://github.com/k1LoW/tcpdp/pull/38) ([k1LoW](https://github.com/k1LoW))
* Support MySQL client default-character-set [#37](https://github.com/k1LoW/tcpdp/pull/37) ([k1LoW](https://github.com/k1LoW))
* Separate tcpdp/dumper to tcpdp/dumper and tcpdp/dumper/* [#36](https://github.com/k1LoW/tcpdp/pull/36) ([k1LoW](https://github.com/k1LoW))
* Let's stop vendor [#35](https://github.com/k1LoW/tcpdp/pull/35) ([pyama86](https://github.com/pyama86))
* Fix busy loop [#34](https://github.com/k1LoW/tcpdp/pull/34) ([k1LoW](https://github.com/k1LoW))
* Support parse MySQL compressed packet [#33](https://github.com/k1LoW/tcpdp/pull/33) ([k1LoW](https://github.com/k1LoW))
* Use LABEL instead of MAINTAINER (for deprecation) [#32](https://github.com/k1LoW/tcpdp/pull/32) ([hfm](https://github.com/hfm))

## [v0.9.1](https://github.com/k1LoW/tcpdp/compare/v0.9.0...v0.9.1) (2018-09-27)

* Fix parsing `--target` and generating BPF Filter  [#31](https://github.com/k1LoW/tcpdp/pull/31) ([k1LoW](https://github.com/k1LoW))
* Remove `-X $(PKG).date=` from -ldflags and add `-X $(PKG).version=` [#30](https://github.com/k1LoW/tcpdp/pull/30) ([k1LoW](https://github.com/k1LoW))
* Fix `make crossbuild` [#29](https://github.com/k1LoW/tcpdp/pull/29) ([k1LoW](https://github.com/k1LoW))

## [v0.9.0](https://github.com/k1LoW/tcpdp/compare/v0.8.0...v0.9.0) (2018-09-25)

* I want to do arbitrary processing after rotate [#28](https://github.com/k1LoW/tcpdp/pull/28) ([pyama86](https://github.com/pyama86))
* support any ip sniffing [#27](https://github.com/k1LoW/tcpdp/pull/27) ([pyama86](https://github.com/pyama86))

## [v0.8.0](https://github.com/k1LoW/tcpdp/compare/v0.7.0...v0.8.0) (2018-09-24)

* [BREAKING]Fix HexDumper output [#26](https://github.com/k1LoW/tcpdp/pull/26) ([k1LoW](https://github.com/k1LoW))
* Add more values to error log when `probe` [#25](https://github.com/k1LoW/tcpdp/pull/25) ([k1LoW](https://github.com/k1LoW))
* [BREAKING]Fix *Dumber Read when direction = Unknown [#24](https://github.com/k1LoW/tcpdp/pull/24) ([k1LoW](https://github.com/k1LoW))
* Remove dumper.ReadInitialDumpValues [#23](https://github.com/k1LoW/tcpdp/pull/23) ([k1LoW](https://github.com/k1LoW))

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
