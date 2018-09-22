package main

import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/xo/dburl"
)

func main() {
	for i := 0; i < 5; i++ {
		urlstr := "my://root:mypass@127.0.0.1:33308/testdb"
		db, err := dburl.Open(urlstr)
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

		db.Close()
	}
}
