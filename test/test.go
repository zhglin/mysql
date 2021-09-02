package main

import (
	"github.com/opentrx/mysql/v2"
	"github.com/opentrx/mysql/v2/pkg/database/sql"
	"time"
)

func main() {
	dsn := "root:123456@tcp(127.0.0.1:3306)/seata_order?timeout=5s&readTimeout=5s&writeTimeout=1s&parseTime=true&loc=Local&charset=utf8mb4,utf8"
	mysql.RegisterResource(dsn)

	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetMaxIdleConns(20)
	sqlDB.SetConnMaxLifetime(4 * time.Hour)
}

