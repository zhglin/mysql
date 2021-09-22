// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2012 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	//"database/sql"
	//"database/sql/driver"
	"github.com/opentrx/mysql/v2/pkg/database/sql"
	"github.com/opentrx/mysql/v2/pkg/database/sql/driver"
	"github.com/opentrx/seata-golang/v2/pkg/client/config"
	"github.com/pingcap/parser"
	"github.com/pingcap/parser/ast"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const XID = "XID"
const GlobalLock = "GlobalLock"

type connCtx struct {
	xid                string
	branchID           int64
	lockKeys           []string
	sqlUndoItemsBuffer []*sqlUndoLog
}

// mysql链接
type mysqlConn struct {
	buf              buffer   // 缓冲
	netConn          net.Conn // 网络链接
	rawConn          net.Conn // underlying connection when netConn is TLS connection.
	affectedRows     uint64   // 服务器端返回的受影响的行
	insertId         uint64   // 服务器端返回的插入的id
	cfg              *Config  // 配置
	maxAllowedPacket int      // 设定server所接受的包的大小
	maxWriteSize     int      // 最大写入包大小

	writeTimeout time.Duration // 写入的超时时间
	flags        clientFlag    // 功能标记 https://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags
	status       statusFlag    // 服务器返回的状态信息
	sequence     uint8         // 在这条链接上发送的报文序列号，通常来说是相邻两个报文的序列号是递增的，发送一次+1
	parseTime    bool          // 是否将时间值解析成time.time
	// 是否进行链接重置
	reset bool // set when the Go SQL package calls ResetSession

	// for context support (Go 1.8+)
	// 超时的context可能会导致客户端查询超时，但是服务端未超时，那这条链接要关闭
	// 重用可能导致返回已超时客户端的查询结果
	watching bool // 是否在watch中，是否使用中。只有正常查询结束才会设置成false
	watcher  chan<- context.Context
	// 是否关闭链接
	closech  chan struct{}
	finished chan<- struct{}
	// 终止的原因
	canceled atomicError // set non-nil if conn is canceled
	// conn是否已关闭 先关闭closech
	closed atomicBool // set when conn is closed, before closech is closed

	ctx *connCtx
}

func (ctx *connCtx) AppendLockKey(lockKey string) {
	if ctx.lockKeys == nil {
		ctx.lockKeys = make([]string, 0)
	}
	ctx.lockKeys = append(ctx.lockKeys, lockKey)
}

func (ctx *connCtx) AppendUndoItem(undoLog *sqlUndoLog) {
	if ctx.sqlUndoItemsBuffer == nil {
		ctx.sqlUndoItemsBuffer = make([]*sqlUndoLog, 0)
	}
	ctx.sqlUndoItemsBuffer = append(ctx.sqlUndoItemsBuffer, undoLog)
}

// Handles parameters set in DSN after the connection is established
// 处理连接建立后在配置中设置的参数
func (mc *mysqlConn) handleParams() (err error) {
	var cmdSet strings.Builder
	for param, val := range mc.cfg.Params {
		switch param {
		// Charset: character_set_connection, character_set_client, character_set_results
		// 直接设置链接级的编码 忽略响应报文
		case "charset":
			charsets := strings.Split(val, ",")
			for i := range charsets {
				// ignore errors here - a charset may not exist
				err = mc.exec("SET NAMES " + charsets[i])
				if err == nil {
					break
				}
			}
			if err != nil {
				return
			}

		// Other system vars accumulated in a single SET command
		// 在单个SET命令中积累的其他系统变量
		default:
			if cmdSet.Len() == 0 {
				// Heuristic: 29 chars for each other key=value to reduce reallocations
				// 启发式:每个键值为29个字符，以减少重新分配
				cmdSet.Grow(4 + len(param) + 1 + len(val) + 30*(len(mc.cfg.Params)-1))
				cmdSet.WriteString("SET ")
			} else {
				cmdSet.WriteByte(',')
			}
			cmdSet.WriteString(param)
			cmdSet.WriteByte('=')
			cmdSet.WriteString(val)
		}
	}

	if cmdSet.Len() > 0 {
		err = mc.exec(cmdSet.String())
		if err != nil {
			return
		}
	}

	return
}

// 转换error
func (mc *mysqlConn) markBadConn(err error) error {
	if mc == nil {
		return err
	}
	if err != errBadConnNoWrite {
		return err
	}
	return driver.ErrBadConn
}

func (mc *mysqlConn) Begin() (driver.Tx, error) {
	return mc.begin(false)
}

func (mc *mysqlConn) begin(readOnly bool) (driver.Tx, error) {
	if mc.closed.IsSet() {
		errLog.Print(ErrInvalidConn)
		return nil, driver.ErrBadConn
	}
	var q string
	if readOnly {
		q = "START TRANSACTION READ ONLY"
	} else {
		q = "START TRANSACTION"
	}
	err := mc.exec(q)
	if err == nil {
		// 转换transaction
		return &mysqlTx{mc}, err
	}
	return nil, mc.markBadConn(err)
}

// Close 关闭链接，发送quit报文
func (mc *mysqlConn) Close() (err error) {
	// Makes Close idempotent
	if !mc.closed.IsSet() {
		err = mc.writeCommandPacket(comQuit)
	}

	mc.cleanup()

	return
}

// Closes the network connection and unsets internal variables. Do not call this
// function after successfully authentication, call Close instead. This function
// is called before auth or on auth failure because MySQL will have already
// closed the network connection.
// 关闭网络连接并取消内部变量设置。
// 在身份验证成功后不要调用这个函数，而是调用Close。
// 因为MySQL已经关闭了网络连接，所以在认证失败之前或认证失败时调用这个函数。
func (mc *mysqlConn) cleanup() {
	// 已关闭
	if !mc.closed.TrySet(true) {
		return
	}

	// Makes cleanup idempotent
	// 关闭链接
	close(mc.closech)
	if mc.netConn == nil {
		return
	}
	if err := mc.netConn.Close(); err != nil {
		errLog.Print(err)
	}
}

func (mc *mysqlConn) error() error {
	if mc.closed.IsSet() {
		if err := mc.canceled.Value(); err != nil {
			return err
		}
		return ErrInvalidConn
	}
	return nil
}

func (mc *mysqlConn) Prepare(query string) (driver.Stmt, error) {
	if mc.closed.IsSet() {
		errLog.Print(ErrInvalidConn)
		return nil, driver.ErrBadConn
	}
	// Send command
	err := mc.writeCommandPacketStr(comStmtPrepare, query)
	if err != nil {
		// STMT_PREPARE is safe to retry.  So we can return ErrBadConn here.
		errLog.Print(err)
		return nil, driver.ErrBadConn
	}

	stmt := &mysqlStmt{
		mc:  mc,
		sql: query,
	}

	// Read Result
	columnCount, err := stmt.readPrepareResultPacket()
	if err == nil {
		if stmt.paramCount > 0 {
			if err = mc.readUntilEOF(); err != nil {
				return nil, err
			}
		}

		if columnCount > 0 {
			err = mc.readUntilEOF()
		}
	}

	return stmt, err
}

// query语句中插入参数
func (mc *mysqlConn) interpolateParams(query string, args []driver.Value) (string, error) {
	// Number of ? should be same to len(args)
	// 占位符数量不一致
	if strings.Count(query, "?") != len(args) {
		return "", driver.ErrSkip
	}

	buf, err := mc.buf.takeCompleteBuffer()
	if err != nil {
		// can not take the buffer. Something must be wrong with the connection
		errLog.Print(err)
		return "", ErrInvalidConn
	}
	buf = buf[:0]
	argPos := 0

	for i := 0; i < len(query); i++ {
		// 没有占位符 直接跳过
		q := strings.IndexByte(query[i:], '?')
		if q == -1 {
			buf = append(buf, query[i:]...)
			break
		}

		buf = append(buf, query[i:i+q]...)
		i += q

		arg := args[argPos]
		argPos++

		if arg == nil {
			buf = append(buf, "NULL"...)
			continue
		}

		switch v := arg.(type) {
		case int64:
			buf = strconv.AppendInt(buf, v, 10)
		case uint64:
			// Handle uint64 explicitly because our custom ConvertValue emits unsigned values
			buf = strconv.AppendUint(buf, v, 10)
		case float64:
			buf = strconv.AppendFloat(buf, v, 'g', -1, 64)
		case bool:
			if v {
				buf = append(buf, '1')
			} else {
				buf = append(buf, '0')
			}
		case time.Time:
			if v.IsZero() {
				buf = append(buf, "'0000-00-00'"...)
			} else {
				buf = append(buf, '\'')
				buf, err = appendDateTime(buf, v.In(mc.cfg.Loc))
				if err != nil {
					return "", err
				}
				buf = append(buf, '\'')
			}
		case json.RawMessage:
			buf = append(buf, '\'')
			if mc.status&statusNoBackslashEscapes == 0 {
				buf = escapeBytesBackslash(buf, v)
			} else {
				buf = escapeBytesQuotes(buf, v)
			}
			buf = append(buf, '\'')
		case []byte:
			if v == nil {
				buf = append(buf, "NULL"...)
			} else {
				buf = append(buf, "_binary'"...)
				if mc.status&statusNoBackslashEscapes == 0 {
					buf = escapeBytesBackslash(buf, v)
				} else {
					buf = escapeBytesQuotes(buf, v)
				}
				buf = append(buf, '\'')
			}
		case string:
			buf = append(buf, '\'')
			if mc.status&statusNoBackslashEscapes == 0 {
				buf = escapeStringBackslash(buf, v)
			} else {
				buf = escapeStringQuotes(buf, v)
			}
			buf = append(buf, '\'')
		default:
			return "", driver.ErrSkip
		}

		if len(buf)+4 > mc.maxAllowedPacket {
			return "", driver.ErrSkip
		}
	}
	if argPos != len(args) {
		return "", driver.ErrSkip
	}
	return string(buf), nil
}

func (mc *mysqlConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	if mc.closed.IsSet() {
		errLog.Print(ErrInvalidConn)
		return nil, driver.ErrBadConn
	}
	if len(args) != 0 {
		if !mc.cfg.InterpolateParams {
			return nil, driver.ErrSkip
		}
		// try to interpolate the parameters to save extra roundtrips for preparing and closing a statement
		// 尝试插入参数，以节省准备和关闭语句所需的额外往返
		prepared, err := mc.interpolateParams(query, args)
		if err != nil {
			return nil, err
		}
		query = prepared
	}
	mc.affectedRows = 0
	mc.insertId = 0

	err := mc.exec(query)
	if err == nil {
		return &mysqlResult{
			affectedRows: int64(mc.affectedRows),
			insertId:     int64(mc.insertId),
		}, err
	}
	return nil, mc.markBadConn(err)
}

func (mc *mysqlConn) execAlways(query string, args []driver.Value) (driver.Result, error) {
	stmt, err := mc.Prepare(query)
	if err != nil {
		return nil, err
	}
	s := stmt.(*mysqlStmt)

	nargs := make([]driver.Value, len(args))
	for i, arg := range args {
		nargs[i], err = driver.DefaultParameterConverter.ConvertValue(arg)
		if err != nil {
			return nil, fmt.Errorf("sql: converting argument %t type: %v", arg, err)
		}
	}

	// Send command
	err = s.writeExecutePacket(nargs)
	if err != nil {
		return nil, s.mc.markBadConn(err)
	}

	mc.affectedRows = 0
	mc.insertId = 0

	// Read Result
	resLen, err := mc.readResultSetHeaderPacket()
	if err != nil {
		return nil, err
	}

	if resLen > 0 {
		// Columns
		if err = mc.readUntilEOF(); err != nil {
			return nil, err
		}

		// Rows
		if err := mc.readUntilEOF(); err != nil {
			return nil, err
		}
	}

	if err := mc.discardResults(); err != nil {
		return nil, err
	}

	return &mysqlResult{
		affectedRows: int64(mc.affectedRows),
		insertId:     int64(mc.insertId),
	}, nil
}

// Internal function to execute commands
// 执行命令的内部功能 接收不处理响应信息
func (mc *mysqlConn) exec(query string) error {
	// Send command
	if err := mc.writeCommandPacketStr(comQuery, query); err != nil {
		return mc.markBadConn(err)
	}

	// Read Result
	resLen, err := mc.readResultSetHeaderPacket()
	if err != nil {
		return err
	}

	if resLen > 0 {
		// columns
		if err := mc.readUntilEOF(); err != nil {
			return err
		}

		// rows
		if err := mc.readUntilEOF(); err != nil {
			return err
		}
	}

	return mc.discardResults()
}

func (mc *mysqlConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	return mc.query(query, args)
}

func (mc *mysqlConn) prepareQuery(query string, args []driver.Value) (*binaryRows, error) {
	stmt, err := mc.Prepare(query)
	if err != nil {
		return nil, err
	}
	s := stmt.(*mysqlStmt)
	return s.query(args)
}

func (mc *mysqlConn) readPrepareResultPacket() (uint16, int, error) {
	data, err := mc.readPacket()
	if err == nil {
		// packet indicator [1 byte]
		if data[0] != iOK {
			return 0, 0, mc.handleErrorPacket(data)
		}

		// Column count [16 bit uint]
		columnCount := binary.LittleEndian.Uint16(data[5:7])

		// Param count [16 bit uint]
		paramCount := int(binary.LittleEndian.Uint16(data[7:9]))

		return columnCount, paramCount, nil
	}
	return 0, 0, err
}

func (mc *mysqlConn) query(query string, args []driver.Value) (*textRows, error) {
	if mc.closed.IsSet() {
		errLog.Print(ErrInvalidConn)
		return nil, driver.ErrBadConn
	}
	if len(args) != 0 {
		if !mc.cfg.InterpolateParams {
			return nil, driver.ErrSkip
		}
		// try client-side prepare to reduce roundtrip
		prepared, err := mc.interpolateParams(query, args)
		if err != nil {
			return nil, err
		}
		query = prepared
	}
	// Send command
	err := mc.writeCommandPacketStr(comQuery, query)
	if err == nil {
		// Read Result
		var resLen int
		resLen, err = mc.readResultSetHeaderPacket()
		if err == nil {
			rows := new(textRows)
			rows.mc = mc

			if resLen == 0 {
				rows.rs.done = true

				switch err := rows.NextResultSet(); err {
				case nil, io.EOF:
					return rows, nil
				default:
					return nil, err
				}
			}

			// Columns
			rows.rs.columns, err = mc.readColumns(resLen)
			return rows, err
		}
	}
	return nil, mc.markBadConn(err)
}

// Gets the value of the given MySQL System Variable
// The returned byte slice is only valid until the next read
// 获取给定MySQL系统变量的值。返回的字节片只在下一次读取时有效
func (mc *mysqlConn) getSystemVar(name string) ([]byte, error) {
	// Send command
	if err := mc.writeCommandPacketStr(comQuery, "SELECT @@"+name); err != nil {
		return nil, err
	}

	// Read Result resLen结果集对应的column_count
	resLen, err := mc.readResultSetHeaderPacket()
	if err == nil {
		rows := new(textRows)
		rows.mc = mc
		rows.rs.columns = []mysqlField{{fieldType: fieldTypeVarChar}}

		// 跳过columns包
		if resLen > 0 {
			// Columns
			if err := mc.readUntilEOF(); err != nil {
				return nil, err
			}
		}

		// 只读取一行结果
		dest := make([]driver.Value, resLen)
		if err = rows.readRow(dest); err == nil {
			return dest[0].([]byte), mc.readUntilEOF() // 读取eof包
		}
	}
	return nil, err
}

// finish is called when the query has canceled.
// 在查询已被context取消时调用。
func (mc *mysqlConn) cancel(err error) {
	mc.canceled.Set(err)
	mc.cleanup()
}

// finish is called when the query has succeeded.
// 当查询成功时调用Finish。
func (mc *mysqlConn) finish() {
	if !mc.watching || mc.finished == nil {
		return
	}
	// 调用finish时，可能已经context超时了
	select {
	case mc.finished <- struct{}{}:
		mc.watching = false
	case <-mc.closech:
	}
}

// Ping implements driver.Pinger interface
func (mc *mysqlConn) Ping(ctx context.Context) (err error) {
	if mc.closed.IsSet() {
		errLog.Print(ErrInvalidConn)
		return driver.ErrBadConn
	}

	if err = mc.watchCancel(ctx); err != nil {
		return
	}
	defer mc.finish()

	if err = mc.writeCommandPacket(comPing); err != nil {
		return mc.markBadConn(err)
	}

	return mc.readResultOK()
}

// BeginTx implements driver.ConnBeginTx interface
func (mc *mysqlConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if mc.closed.IsSet() {
		return nil, driver.ErrBadConn
	}

	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}
	defer mc.finish()

	if sql.IsolationLevel(opts.Isolation) != sql.LevelDefault {
		level, err := mapIsolationLevel(opts.Isolation)
		if err != nil {
			return nil, err
		}
		err = mc.exec("SET TRANSACTION ISOLATION LEVEL " + level)
		if err != nil {
			return nil, err
		}
	}

	// 开启事务 设置分布式事务信息
	val := ctx.Value(XID)
	if val != nil {
		if xid, ok := val.(string); ok {
			mc.ctx = &connCtx{
				xid:                xid,
				lockKeys:           make([]string, 0),
				sqlUndoItemsBuffer: make([]*sqlUndoLog, 0),
			}
		}
	}

	return mc.begin(opts.ReadOnly)
}

func (mc *mysqlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}

	rows, err := mc.query(query, dargs)
	if err != nil {
		mc.finish()
		return nil, err
	}
	rows.finish = mc.finish
	return rows, err
}

func (mc *mysqlConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}
	defer mc.finish()

	globalLock := false
	val := ctx.Value(GlobalLock)
	if val != nil {
		globalLock = val.(bool)
	}

	if globalLock {
		executable, err := executable(mc, query, dargs)
		if err != nil {
			return nil, err
		}
		if !executable {
			return nil, fmt.Errorf("data resource locked by seata transaction coordinator")
		}
	}

	return mc.Exec(query, dargs)
}

func (mc *mysqlConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if err := mc.watchCancel(ctx); err != nil {
		return nil, err
	}

	stmt, err := mc.Prepare(query)
	mc.finish()
	if err != nil {
		return nil, err
	}

	select {
	default:
	case <-ctx.Done():
		stmt.Close()
		return nil, ctx.Err()
	}
	return stmt, nil
}

func (stmt *mysqlStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := stmt.mc.watchCancel(ctx); err != nil {
		return nil, err
	}

	rows, err := stmt.query(dargs)
	if err != nil {
		stmt.mc.finish()
		return nil, err
	}
	rows.finish = stmt.mc.finish
	return rows, err
}

func (stmt *mysqlStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	dargs, err := namedValueToValue(args)
	if err != nil {
		return nil, err
	}

	if err := stmt.mc.watchCancel(ctx); err != nil {
		return nil, err
	}
	defer stmt.mc.finish()

	globalLock := false
	val := ctx.Value(GlobalLock)
	if val != nil {
		globalLock = val.(bool)
	}

	if globalLock {
		executable, err := executable(stmt.mc, stmt.sql, dargs)
		if err != nil {
			return nil, err
		}
		if !executable {
			return nil, fmt.Errorf("data resource locked by seata transaction coordinator")
		}
	}

	return stmt.Exec(dargs)
}

func executable(mc *mysqlConn, sql string, args []driver.Value) (bool, error) {
	parser := parser.New()
	act, _ := parser.ParseOneStmt(sql, "", "")
	deleteStmt, isDelete := act.(*ast.DeleteStmt)
	if isDelete {
		executor := &globalLockExecutor{
			mc:          mc,
			originalSQL: sql,
			isUpdate:    false,
			deleteStmt:  deleteStmt,
			args:        args,
		}
		return executor.Executable(config.GetATConfig().LockRetryInterval, config.GetATConfig().LockRetryTimes)
	}

	updateStmt, isUpdate := act.(*ast.UpdateStmt)
	if isUpdate {
		executor := &globalLockExecutor{
			mc:          mc,
			originalSQL: sql,
			isUpdate:    true,
			updateStmt:  updateStmt,
			args:        args,
		}
		return executor.Executable(config.GetATConfig().LockRetryInterval, config.GetATConfig().LockRetryTimes)
	}
	return true, nil
}

// 监听context，所有具有context的参数都需要进行调用
func (mc *mysqlConn) watchCancel(ctx context.Context) error {
	// 说明上个请求是超时关闭的，非正常查询结束放回连接池的。
	if mc.watching {
		// Reach here if canceled,
		// so the connection is already invalid
		mc.cleanup()
		return nil
	}
	// When ctx is already cancelled, don't watch it.
	// 当ctx已经取消，不要看它。
	if err := ctx.Err(); err != nil {
		return err
	}
	// When ctx is not cancellable, don't watch it.
	// 当ctx不能取消时，不要看它。
	if ctx.Done() == nil {
		return nil
	}
	// When watcher is not alive, can't watch it.
	// 当watcher不是活着的时候，就不能看它了。
	if mc.watcher == nil {
		return nil
	}

	mc.watching = true // 标记已经在使用中了
	mc.watcher <- ctx  // 写入当前的context
	return nil
}

// 开启监听context
func (mc *mysqlConn) startWatcher() {
	watcher := make(chan context.Context, 1)
	mc.watcher = watcher
	finished := make(chan struct{})
	mc.finished = finished
	go func() {
		for {
			var ctx context.Context
			select {
			case ctx = <-watcher: // 获取context
			case <-mc.closech: // 已关闭
				return
			}

			select {
			case <-ctx.Done(): // 如果ctx先被取消了
				mc.cancel(ctx.Err())
			case <-finished: // 查询完成
			case <-mc.closech: // 已关闭，退出监听
				return
			}
		}
	}()
}

// CheckNamedValue NamedValueChecker接口实现
func (mc *mysqlConn) CheckNamedValue(nv *driver.NamedValue) (err error) {
	nv.Value, err = converter{}.ConvertValue(nv.Value)
	return
}

// ResetSession implements driver.SessionResetter.
// (From Go 1.10)
func (mc *mysqlConn) ResetSession(ctx context.Context) error {
	if mc.closed.IsSet() {
		return driver.ErrBadConn
	}
	mc.reset = true
	return nil
}

// IsValid implements driver.Validator interface
// (From Go 1.15)
func (mc *mysqlConn) IsValid() bool {
	return !mc.closed.IsSet()
}
