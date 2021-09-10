// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2013 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"io"
	"net"
	"time"
)

const defaultBufSize = 4096
const maxCachedBufSize = 256 * 1024

// A buffer which is used for both reading and writing.
// This is possible since communication on each connection is synchronous.
// In other words, we can't write and read simultaneously on the same connection.
// The buffer is similar to bufio.Reader / Writer but zero-copy-ish
// Also highly optimized for this particular use case.
// This buffer is backed by two byte slices in a double-buffering scheme
// 一种同时用于读和写的缓冲区。这是可能的，因为每个连接上的通信是同步的。
// 换句话说，我们不能在同一个连接上同时写和读。缓冲区类似于bufio.Reader / Writer，但几乎是零拷贝，也为这个特殊的用例进行了高度优化。
// 在双缓冲方案中，这个缓冲区由两个字节片支持
type buffer struct {
	// Buf是一个长度和容量相等的字节缓冲区。指向dbuf或者新建的buf
	buf []byte // buf is a byte buffer who's length and capacity are equal.
	nc  net.Conn
	// buf中未使用的数据起始下标
	idx int
	// 当前缓冲区中未返回的数据长度
	length int
	// 读取的超时时间
	timeout time.Duration
	// 双buf缓冲区，
	dbuf [2][]byte // dbuf is an array with the two byte slices that back this buffer
	// flipcnt&1用来指定dbuf的index
	flipcnt uint // flipccnt is the current buffer counter for double-buffering
}

// newBuffer allocates and returns a new buffer.
// 分配并返回一个新的缓冲区。
func newBuffer(nc net.Conn) buffer {
	fg := make([]byte, defaultBufSize)
	return buffer{
		buf:  fg,
		nc:   nc,
		dbuf: [2][]byte{fg, nil},
	}
}

// flip replaces the active buffer with the background buffer
// this is a delayed flip that simply increases the buffer counter;
// the actual flip will be performed the next time we call `buffer.fill`
// Flip将活动缓冲区替换为后台缓冲区这是一个延迟翻转，只是增加缓冲区计数器;
// 实际的翻转将在下一次调用"buffer.fill"时执行
func (b *buffer) flip() {
	b.flipcnt += 1
}

// fill reads into the buffer until at least _need_ bytes are in it
// 填入缓冲区，直到其中至少有_need_字节
func (b *buffer) fill(need int) error {
	n := b.length
	// fill data into its double-buffering target: if we've called
	// flip on this buffer, we'll be copying to the background buffer,
	// and then filling it with network data; otherwise we'll just move
	// the contents of the current buffer to the front before filling it
	// 将数据填充到它的双缓冲目标中:如果我们在这个缓冲区上调用flip，我们将复制到后台缓冲区，然后用网络数据填充它;
	// 否则，我们只会在填充缓冲区之前将当前缓冲区的内容移动到前面
	dest := b.dbuf[b.flipcnt&1]

	// grow buffer if necessary to fit the whole packet.
	// 如有必要，增加缓冲区以适应整个数据包。需要的数据长度大于缓冲区的长度
	if need > len(dest) {
		// Round up to the next multiple of the default size
		// 四舍五入到默认大小的下一个倍数
		dest = make([]byte, ((need/defaultBufSize)+1)*defaultBufSize)

		// if the allocated buffer is not too large, move it to backing storage
		// to prevent extra allocations on applications that perform large reads
		// 如果分配的缓冲区不是太大，将它移动到后备存储，以防止执行大型读取的应用程序额外的分配
		// 超过最大缓冲区长度就单独使用
		if len(dest) <= maxCachedBufSize {
			b.dbuf[b.flipcnt&1] = dest
		}
	}

	// if we're filling the fg buffer, move the existing data to the start of it.
	// if we're filling the bg buffer, copy over the data
	// 如果我们正在填充fg缓冲区，将现有数据移动到它的开始。
	// 如果我们正在填充bg缓冲区，复制数据
	// 当前的缓冲区中还有剩余的数据，复制到新的缓冲区中
	if n > 0 {
		copy(dest[:n], b.buf[b.idx:])
	}

	b.buf = dest
	b.idx = 0

	for {
		// 设置读取的超时时间
		if b.timeout > 0 {
			if err := b.nc.SetReadDeadline(time.Now().Add(b.timeout)); err != nil {
				return err
			}
		}

		// 读取链接上的数据
		nn, err := b.nc.Read(b.buf[n:])
		n += nn

		switch err {
		case nil:
			// 读取长度不足
			if n < need {
				continue
			}
			b.length = n
			return nil

		case io.EOF:
			if n >= need {
				b.length = n
				return nil
			}
			return io.ErrUnexpectedEOF

		default:
			return err
		}
	}
}

// returns next N bytes from buffer.
// The returned slice is only guaranteed to be valid until the next read
// 从缓冲区返回下一个N字节。返回的切片只能保证在下一次读取之前有效
func (b *buffer) readNext(need int) ([]byte, error) {
	if b.length < need {
		// refill 重新从链接上读取数据
		if err := b.fill(need); err != nil {
			return nil, err
		}
	}

	offset := b.idx
	b.idx += need
	b.length -= need
	return b.buf[offset:b.idx], nil
}

// takeBuffer returns a buffer with the requested size.
// If possible, a slice from the existing buffer is returned.
// Otherwise a bigger buffer is made.
// Only one buffer (total) can be used at a time.
// takeBuffer返回一个具有请求大小的缓冲区。
// 如果可能，将返回现有缓冲区中的一个片。否
// 则将生成一个更大的缓冲区。一次只能使用一个缓冲区(总共)。
func (b *buffer) takeBuffer(length int) ([]byte, error) {
	// 缓冲区中还有未使用的数据
	if b.length > 0 {
		return nil, ErrBusyBuffer
	}

	// test (cheap) general case first
	// 需要的缓冲区比现有的缓冲区小
	if length <= cap(b.buf) {
		return b.buf[:length], nil
	}

	// 比现有的缓冲区大，比最大的缓冲区小
	if length < maxPacketSize {
		b.buf = make([]byte, length)
		return b.buf, nil
	}

	// buffer is larger than we want to store.
	// 比最大的缓冲区大
	return make([]byte, length), nil
}

// takeSmallBuffer is shortcut which can be used if length is
// known to be smaller than defaultBufSize.
// Only one buffer (total) can be used at a time.
// takeSmallBuffer是一个快捷方式，如果已知长度小于defaultBufSize，则可以使用它。
// 一次只能使用一个缓冲区(总共)。
func (b *buffer) takeSmallBuffer(length int) ([]byte, error) {
	if b.length > 0 {
		return nil, ErrBusyBuffer
	}
	return b.buf[:length], nil
}

// takeCompleteBuffer returns the complete existing buffer.
// This can be used if the necessary buffer size is unknown.
// cap and len of the returned buffer will be equal.
// Only one buffer (total) can be used at a time.
// takeCompleteBuffer返回完整的现有缓冲区。
// 如果需要的缓冲区大小未知，则可以使用此方法。
// 返回的缓冲区的cap和len值相等。
// 每次只能使用一个buffer (total)
func (b *buffer) takeCompleteBuffer() ([]byte, error) {
	if b.length > 0 {
		return nil, ErrBusyBuffer
	}
	return b.buf, nil
}

// store stores buf, an updated buffer, if its suitable to do so.
// Store存储buf，一个更新的缓冲区，如果它适合这样做的话。
func (b *buffer) store(buf []byte) error {
	if b.length > 0 {
		return ErrBusyBuffer
	} else if cap(buf) <= maxPacketSize && cap(buf) > cap(b.buf) {
		b.buf = buf[:cap(buf)]
	}
	return nil
}
