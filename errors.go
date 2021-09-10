// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2013 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"errors"
	"fmt"
	"log"
	"os"
)

// Various errors the driver might return. Can change between driver versions.
var (
	ErrInvalidConn       = errors.New("invalid connection")                            // 无效的连接
	ErrMalformPkt        = errors.New("malformed packet")                              // 畸形的包
	ErrNoTLS             = errors.New("TLS requested but server does not support TLS") // 请求TLS，但服务器不支持TLS
	ErrCleartextPassword = errors.New("this user requires clear text authentication. If you still want to use it, please add 'allowCleartextPasswords=1' to your DSN")
	ErrNativePassword    = errors.New("this user requires mysql native password authentication.")
	ErrOldPassword       = errors.New("this user requires old password authentication. If you still want to use it, please add 'allowOldPasswords=1' to your DSN. See also https://github.com/go-sql-driver/mysql/wiki/old_passwords")
	ErrUnknownPlugin     = errors.New("this authentication plugin is not supported")
	ErrOldProtocol       = errors.New("MySQL server does not support required protocol 41+")                                          // MySQL服务器不支持41+协议
	ErrPktSync           = errors.New("commands out of sync. You can't run this command now")                                         // 命令不同步。你现在不能运行这个命令
	ErrPktSyncMul        = errors.New("commands out of sync. Did you run multiple statements at once?")                               // 命令不同步。您是否同时运行多个语句?
	ErrPktTooLarge       = errors.New("packet for query is too large. Try adjusting the 'max_allowed_packet' variable on the server") // 查询报文过大。处理步骤尝试在服务器上调整'max_allowed_packet'变量
	ErrBusyBuffer        = errors.New("busy buffer")

	// errBadConnNoWrite is used for connection errors where nothing was sent to the database yet.
	// If this happens first in a function starting a database interaction, it should be replaced by driver.ErrBadConn
	// to trigger a resend.
	// See https://github.com/go-sql-driver/mysql/pull/302
	errBadConnNoWrite = errors.New("bad connection")
)

var errLog = Logger(log.New(os.Stderr, "[mysql] ", log.Ldate|log.Ltime|log.Lshortfile))

// Logger is used to log critical error messages.
type Logger interface {
	Print(v ...interface{})
}

// SetLogger is used to set the logger for critical errors.
// The initial logger is os.Stderr.
func SetLogger(logger Logger) error {
	if logger == nil {
		return errors.New("logger is nil")
	}
	errLog = logger
	return nil
}

// MySQLError is an error type which represents a single MySQL error
// 是一个错误类型，它代表一个单一的MySQL错误
type MySQLError struct {
	Number  uint16
	Message string
}

func (me *MySQLError) Error() string {
	return fmt.Sprintf("Error %d: %s", me.Number, me.Message)
}
