// Copyright (c) 2016 Uber Technologies, Inc.
// Copyright (c) 2017 Hiroaki Nakamura
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package ltsv

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// For JSON-escaping; see ltsvEncoder.safeAddString below.
const hex = "0123456789abcdef"

type ltsvEncoder struct {
	*zapcore.EncoderConfig
	buf            *buffer.Buffer
	spaced         bool // include spaces after colons and commas in JSON
	openNamespaces int

	nestedLevel  int
	justAfterKey bool
}

var bufferpool = buffer.NewPool()

var ltsvPool = sync.Pool{New: func() interface{} {
	return &ltsvEncoder{}
}}

func getLTSVEncoder() *ltsvEncoder {
	return ltsvPool.Get().(*ltsvEncoder)
}

func putLTSVEncoder(enc *ltsvEncoder) {
	enc.EncoderConfig = nil
	enc.buf = nil
	enc.spaced = false
	enc.openNamespaces = 0
	ltsvPool.Put(enc)
}

// NewLTSVEncoder creates a line-oriented LTSV encoder.
func NewLTSVEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	return newLTSVEncoder(cfg, false)
}

func newLTSVEncoder(cfg zapcore.EncoderConfig, spaced bool) *ltsvEncoder {
	return &ltsvEncoder{
		EncoderConfig: &cfg,
		buf:           bufferpool.Get(),
		spaced:        spaced,
	}
}

func (enc *ltsvEncoder) AddArray(key string, arr zapcore.ArrayMarshaler) error {
	enc.addKey(key)
	return enc.AppendArray(arr)
}

func (enc *ltsvEncoder) AddObject(key string, obj zapcore.ObjectMarshaler) error {
	enc.addKey(key)
	return enc.AppendObject(obj)
}

func (enc *ltsvEncoder) AddBinary(key string, val []byte) {
	enc.AddString(key, base64.StdEncoding.EncodeToString(val))
}

func (enc *ltsvEncoder) AddByteString(key string, val []byte) {
	enc.addKey(key)
	enc.AppendByteString(val)
}

func (enc *ltsvEncoder) AddBool(key string, val bool) {
	enc.addKey(key)
	enc.AppendBool(val)
}

func (enc *ltsvEncoder) AddComplex128(key string, val complex128) {
	enc.addKey(key)
	enc.AppendComplex128(val)
}

func (enc *ltsvEncoder) AddDuration(key string, val time.Duration) {
	enc.addKey(key)
	enc.AppendDuration(val)
}

func (enc *ltsvEncoder) AddFloat64(key string, val float64) {
	enc.addKey(key)
	enc.AppendFloat64(val)
}

func (enc *ltsvEncoder) AddInt64(key string, val int64) {
	enc.addKey(key)
	enc.AppendInt64(val)
}

func (enc *ltsvEncoder) AddReflected(key string, obj interface{}) error {
	marshaled, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	enc.addKey(key)
	_, err = enc.buf.Write(marshaled)
	return err
}

func (enc *ltsvEncoder) OpenNamespace(key string) {
	enc.addKey(key)
	enc.buf.AppendByte('{')
	enc.openNamespaces++
}

func (enc *ltsvEncoder) AddString(key, val string) {
	enc.addKey(key)
	enc.AppendString(val)
}

func (enc *ltsvEncoder) AddTime(key string, val time.Time) {
	enc.addKey(key)
	enc.AppendTime(val)
}

func (enc *ltsvEncoder) AddUint64(key string, val uint64) {
	enc.addKey(key)
	enc.AppendUint64(val)
}

func (enc *ltsvEncoder) AppendArray(arr zapcore.ArrayMarshaler) error {
	enc.addElementSeparator()
	enc.buf.AppendByte('[')
	enc.nestedLevel++
	err := arr.MarshalLogArray(enc)
	enc.nestedLevel--
	enc.buf.AppendByte(']')
	return err
}

func (enc *ltsvEncoder) AppendObject(obj zapcore.ObjectMarshaler) error {
	enc.addElementSeparator()
	enc.buf.AppendByte('{')
	enc.nestedLevel++
	err := obj.MarshalLogObject(enc)
	enc.nestedLevel--
	enc.buf.AppendByte('}')
	return err
}

func (enc *ltsvEncoder) AppendBool(val bool) {
	enc.addElementSeparator()
	enc.buf.AppendBool(val)
}

func (enc *ltsvEncoder) AppendByteString(val []byte) {
	enc.addElementSeparator()
	if enc.nestedLevel == 0 && enc.openNamespaces == 0 {
		enc.safeAddByteString(val)
	} else {
		enc.buf.AppendByte('"')
		enc.safeAddByteString(val)
		enc.buf.AppendByte('"')
	}
}

func (enc *ltsvEncoder) AppendComplex128(val complex128) {
	enc.addElementSeparator()
	// Cast to a platform-independent, fixed-size type.
	r, i := float64(real(val)), float64(imag(val))
	if enc.nestedLevel == 0 && enc.openNamespaces == 0 {
		enc.buf.AppendFloat(r, 64)
		enc.buf.AppendByte('+')
		enc.buf.AppendFloat(i, 64)
		enc.buf.AppendByte('i')
	} else {
		enc.buf.AppendByte('"')
		// Because we're always in a quoted string, we can use strconv without
		// special-casing NaN and +/-Inf.
		enc.buf.AppendFloat(r, 64)
		enc.buf.AppendByte('+')
		enc.buf.AppendFloat(i, 64)
		enc.buf.AppendByte('i')
		enc.buf.AppendByte('"')
	}
}

func (enc *ltsvEncoder) AppendDuration(val time.Duration) {
	cur := enc.buf.Len()
	enc.EncodeDuration(val, enc)
	if cur == enc.buf.Len() {
		// User-supplied EncodeDuration is a no-op. Fall back to nanoseconds to keep
		// JSON valid.
		enc.AppendInt64(int64(val))
	}
}

func (enc *ltsvEncoder) AppendInt64(val int64) {
	enc.addElementSeparator()
	enc.buf.AppendInt(val)
}

func (enc *ltsvEncoder) AppendReflected(val interface{}) error {
	marshaled, err := json.Marshal(val)
	if err != nil {
		return err
	}
	enc.addElementSeparator()
	_, err = enc.buf.Write(marshaled)
	return err
}

func (enc *ltsvEncoder) AppendString(val string) {
	enc.addElementSeparator()
	if enc.nestedLevel == 0 && enc.openNamespaces == 0 {
		enc.safeAddString(val)
	} else {
		enc.buf.AppendByte('"')
		enc.safeAddString(val)
		enc.buf.AppendByte('"')
	}
}

func (enc *ltsvEncoder) AppendTime(val time.Time) {
	cur := enc.buf.Len()
	enc.EncodeTime(val, enc)
	if cur == enc.buf.Len() {
		// User-supplied EncodeTime is a no-op. Fall back to nanos since epoch to keep
		// output JSON valid.
		enc.AppendInt64(val.UnixNano())
	}
}

func (enc *ltsvEncoder) AppendUint64(val uint64) {
	enc.addElementSeparator()
	enc.buf.AppendUint(val)
}

func (enc *ltsvEncoder) AddComplex64(k string, v complex64) { enc.AddComplex128(k, complex128(v)) }
func (enc *ltsvEncoder) AddFloat32(k string, v float32)     { enc.AddFloat64(k, float64(v)) }
func (enc *ltsvEncoder) AddInt(k string, v int)             { enc.AddInt64(k, int64(v)) }
func (enc *ltsvEncoder) AddInt32(k string, v int32)         { enc.AddInt64(k, int64(v)) }
func (enc *ltsvEncoder) AddInt16(k string, v int16)         { enc.AddInt64(k, int64(v)) }
func (enc *ltsvEncoder) AddInt8(k string, v int8)           { enc.AddInt64(k, int64(v)) }
func (enc *ltsvEncoder) AddUint(k string, v uint)           { enc.AddUint64(k, uint64(v)) }
func (enc *ltsvEncoder) AddUint32(k string, v uint32)       { enc.AddUint64(k, uint64(v)) }
func (enc *ltsvEncoder) AddUint16(k string, v uint16)       { enc.AddUint64(k, uint64(v)) }
func (enc *ltsvEncoder) AddUint8(k string, v uint8)         { enc.AddUint64(k, uint64(v)) }
func (enc *ltsvEncoder) AddUintptr(k string, v uintptr)     { enc.AddUint64(k, uint64(v)) }
func (enc *ltsvEncoder) AppendComplex64(v complex64)        { enc.AppendComplex128(complex128(v)) }
func (enc *ltsvEncoder) AppendFloat64(v float64)            { enc.appendFloat(v, 64) }
func (enc *ltsvEncoder) AppendFloat32(v float32)            { enc.appendFloat(float64(v), 32) }
func (enc *ltsvEncoder) AppendInt(v int)                    { enc.AppendInt64(int64(v)) }
func (enc *ltsvEncoder) AppendInt32(v int32)                { enc.AppendInt64(int64(v)) }
func (enc *ltsvEncoder) AppendInt16(v int16)                { enc.AppendInt64(int64(v)) }
func (enc *ltsvEncoder) AppendInt8(v int8)                  { enc.AppendInt64(int64(v)) }
func (enc *ltsvEncoder) AppendUint(v uint)                  { enc.AppendUint64(uint64(v)) }
func (enc *ltsvEncoder) AppendUint32(v uint32)              { enc.AppendUint64(uint64(v)) }
func (enc *ltsvEncoder) AppendUint16(v uint16)              { enc.AppendUint64(uint64(v)) }
func (enc *ltsvEncoder) AppendUint8(v uint8)                { enc.AppendUint64(uint64(v)) }
func (enc *ltsvEncoder) AppendUintptr(v uintptr)            { enc.AppendUint64(uint64(v)) }

func (enc *ltsvEncoder) Clone() zapcore.Encoder {
	clone := enc.clone()
	clone.buf.Write(enc.buf.Bytes())
	return clone
}

func (enc *ltsvEncoder) clone() *ltsvEncoder {
	clone := getLTSVEncoder()
	clone.EncoderConfig = enc.EncoderConfig
	clone.spaced = enc.spaced
	clone.openNamespaces = enc.openNamespaces
	clone.buf = bufferpool.Get()
	return clone
}

func (enc *ltsvEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	final := enc.clone()

	if final.TimeKey != "" {
		final.AddTime(final.TimeKey, ent.Time)
	}
	if final.LevelKey != "" {
		final.addKey(final.LevelKey)
		cur := final.buf.Len()
		final.EncodeLevel(ent.Level, final)
		if cur == final.buf.Len() {
			// User-supplied EncodeLevel was a no-op. Fall back to strings to keep
			// output JSON valid.
			final.AppendString(ent.Level.String())
		}
	}
	if ent.LoggerName != "" && final.NameKey != "" {
		final.addKey(final.NameKey)
		final.AppendString(ent.LoggerName)
	}
	if ent.Caller.Defined && final.CallerKey != "" {
		final.addKey(final.CallerKey)
		cur := final.buf.Len()
		final.EncodeCaller(ent.Caller, final)
		if cur == final.buf.Len() {
			// User-supplied EncodeCaller was a no-op. Fall back to strings to
			// keep output JSON valid.
			final.AppendString(ent.Caller.String())
		}
	}
	if final.MessageKey != "" {
		final.addKey(enc.MessageKey)
		final.AppendString(ent.Message)
	}
	if enc.buf.Len() > 0 {
		final.addElementSeparator()
		final.buf.Write(enc.buf.Bytes())
	}
	addFields(final, fields)
	final.closeOpenNamespaces()
	if ent.Stack != "" && final.StacktraceKey != "" {
		final.AddString(final.StacktraceKey, ent.Stack)
	}
	final.buf.AppendByte('\n')

	ret := final.buf
	putLTSVEncoder(final)
	return ret, nil
}

func (enc *ltsvEncoder) truncate() {
	enc.buf.Reset()
}

func (enc *ltsvEncoder) closeOpenNamespaces() {
	for i := 0; i < enc.openNamespaces; i++ {
		enc.buf.AppendByte('}')
	}
}

func (enc *ltsvEncoder) addKey(key string) {
	enc.addElementSeparator()
	if enc.nestedLevel == 0 && enc.openNamespaces == 0 {
		if strings.ContainsRune(key, ':') {
			panic("LTSV keys must not contain colon ':'")
		}
		enc.safeAddString(key)
		enc.buf.AppendByte(':')
		enc.justAfterKey = true
	} else {
		enc.buf.AppendByte('"')
		enc.safeAddString(key)
		enc.buf.AppendByte('"')
		enc.buf.AppendByte(':')
		if enc.spaced {
			enc.buf.AppendByte(' ')
		}
	}
}

func (enc *ltsvEncoder) addElementSeparator() {
	last := enc.buf.Len() - 1
	if last < 0 {
		return
	}
	if enc.nestedLevel == 0 && enc.openNamespaces == 0 {
		if enc.justAfterKey {
			enc.justAfterKey = false
		} else {
			enc.buf.AppendByte('\t')
		}
	} else {
		switch enc.buf.Bytes()[last] {
		case '{', '[', ':', ',', ' ':
			return
		default:
			enc.buf.AppendByte(',')
			if enc.spaced {
				enc.buf.AppendByte(' ')
			}
		}
	}
}

func (enc *ltsvEncoder) appendFloat(val float64, bitSize int) {
	enc.addElementSeparator()
	switch {
	case math.IsNaN(val):
		enc.buf.AppendString(`"NaN"`)
	case math.IsInf(val, 1):
		enc.buf.AppendString(`"+Inf"`)
	case math.IsInf(val, -1):
		enc.buf.AppendString(`"-Inf"`)
	default:
		enc.buf.AppendFloat(val, bitSize)
	}
}

// safeAddString JSON-escapes a string and appends it to the internal buffer.
// Unlike the standard library's encoder, it doesn't attempt to protect the
// user from browser vulnerabilities or JSONP-related problems.
func (enc *ltsvEncoder) safeAddString(s string) {
	for i := 0; i < len(s); {
		if enc.tryAddRuneSelf(s[i]) {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if enc.tryAddRuneError(r, size) {
			i++
			continue
		}
		enc.buf.AppendString(s[i : i+size])
		i += size
	}
}

// safeAddByteString is no-alloc equivalent of safeAddString(string(s)) for s []byte.
func (enc *ltsvEncoder) safeAddByteString(s []byte) {
	for i := 0; i < len(s); {
		if enc.tryAddRuneSelf(s[i]) {
			i++
			continue
		}
		r, size := utf8.DecodeRune(s[i:])
		if enc.tryAddRuneError(r, size) {
			i++
			continue
		}
		enc.buf.Write(s[i : i+size])
		i += size
	}
}

// tryAddRuneSelf appends b if it is valid UTF-8 character represented in a single byte.
func (enc *ltsvEncoder) tryAddRuneSelf(b byte) bool {
	if b >= utf8.RuneSelf {
		return false
	}
	if 0x20 <= b && b != '\\' && b != '"' {
		enc.buf.AppendByte(b)
		return true
	}
	switch b {
	case '\\', '"':
		enc.buf.AppendByte('\\')
		enc.buf.AppendByte(b)
	case '\n':
		enc.buf.AppendByte('\\')
		enc.buf.AppendByte('n')
	case '\r':
		enc.buf.AppendByte('\\')
		enc.buf.AppendByte('r')
	case '\t':
		enc.buf.AppendByte('\\')
		enc.buf.AppendByte('t')
	default:
		// Encode bytes < 0x20, except for the escape sequences above.
		enc.buf.AppendString(`\u00`)
		enc.buf.AppendByte(hex[b>>4])
		enc.buf.AppendByte(hex[b&0xF])
	}
	return true
}

func (enc *ltsvEncoder) tryAddRuneError(r rune, size int) bool {
	if r == utf8.RuneError && size == 1 {
		enc.buf.AppendString(`\ufffd`)
		return true
	}
	return false
}
