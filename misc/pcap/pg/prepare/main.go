package main

import (
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/xo/dburl"
)

func main() {
	for i := 0; i < 5; i++ {
		urlstr := "pg://postgres:pgpass@127.0.0.1:54322/testdb?sslmode=disable"
		db, err := dburl.Open(urlstr)
		if err != nil {
			panic(err)
		}

		tableRows, err := db.Query(`SELECT CONCAT($1::text, $2::text, $3::text);`, "012345679", "あいうえおかきくけこ", "")
		if err != nil {
			panic(err)
		}
		for tableRows.Next() {
			var (
				res string
			)
			err := tableRows.Scan(&res)
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s\n", res)
		}
		err = tableRows.Close()
		if err != nil {
			panic(err)
		}

		tableRows, err = db.Query(`SELECT $1::int + $2::float + $3::int`, 1, 23.4, 0)
		if err != nil {
			panic(err)
		}
		for tableRows.Next() {
		}
		err = tableRows.Close()
		if err != nil {
			panic(err)
		}

		err = db.Close()
		if err != nil {
			panic(err)
		}
	}
}
