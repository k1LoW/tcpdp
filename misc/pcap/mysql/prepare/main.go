package main

import (
	"database/sql"

	_ "github.com/bLamarche413/mysql"
)

func main() {
	for i := 0; i < 5; i++ {
		db, err := sql.Open("mysql", "root:mypass@tcp(127.0.0.1:33306)/testdb")
		//urlstr := "my://root:mypass@127.0.0.1:33306/testdb"
		//db, err := dburl.Open(urlstr)
		if err != nil {
			panic(err)
		}

		tableRows, err := db.Query(`SELECT CONCAT(?, ?, ?);`, "012345679", "あいうえおかきくけこ", "")
		if err != nil {
			panic(err)
		}
		for tableRows.Next() {
		}
		tableRows.Close()

		tableRows, err = db.Query(`SELECT ? + ? + ?`, 1, 23.4, 0)
		if err != nil {
			panic(err)
		}
		for tableRows.Next() {
		}
		tableRows.Close()

		tableRows, err = db.Query(`SELECT CONCAT(?, ?, ?, " tcpdp is TCP dump tool with custom dumper written in Go.", " tcpdp is TCP dump tool with custom dumper written in Go.", " tcpdp is TCP dump tool with custom dumper written in Go.", " tcpdp is TCP dump tool with custom dumper written in Go.");`,
			"tcpdp", "ティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピー", "")
		if err != nil {
			panic(err)
		}
		for tableRows.Next() {
		}
		tableRows.Close()

		db.Close()
	}
}
