// Package ltsv provides the LTSV encoder for the zap logging library.
// See http://ltsv.org/ for LTSV (Labeled Tab-separated Values),
// https://github.com/uber-go/zap for the zap logging library.
//
// Keys and values are escaped in the same way as JSON strings'
// content (without enclosing double qoutes).
//
// The LTSV encoder panics if a key contains colon ':'.
// Values can contain colon characters.
//
// Nested values (like structs, objects, arrays) are encoded in JSON format.
// See Example (Nested) or Example (Reflected).
package ltsv
