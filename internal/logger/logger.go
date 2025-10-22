/*
 * MIT License
 *
 * Copyright (c) 2025 CVEWatch Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Package logger provides simple logging functionality for CVEWatch.
//
// It supports multiple log levels (DEBUG, INFO, WARN, ERROR) with
// formatted output including timestamps and level prefixes.
package logger

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// LogLevel represents the logging level
type LogLevel int

const (
	// DEBUG log level for detailed debugging information
	DEBUG LogLevel = iota
	// INFO log level for general information
	INFO
	// WARN log level for warnings
	WARN
	// ERROR log level for errors
	ERROR
)

const (
	debugStr = "debug"
	infoStr  = "info"
	warnStr  = "warn"
	errorStr = "error"
)

// Logger provides structured logging functionality
type Logger struct {
	level  LogLevel
	prefix string
}

// NewLogger creates a new logger instance
func NewLogger(level string, prefix string) *Logger {
	var logLevel LogLevel
	switch strings.ToLower(level) {
	case debugStr:
		logLevel = DEBUG
	case infoStr:
		logLevel = INFO
	case warnStr:
		logLevel = WARN
	case errorStr:
		logLevel = ERROR
	default:
		logLevel = INFO
	}

	return &Logger{
		level:  logLevel,
		prefix: prefix,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level <= DEBUG {
		l.log("DEBUG", format, args...)
	}
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level <= INFO {
		l.log("INFO", format, args...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level <= WARN {
		l.log("WARN", format, args...)
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= ERROR {
		l.log("ERROR", format, args...)
	}
}

// log formats and outputs the log message
func (l *Logger) log(level, format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	if l.prefix != "" {
		log.Printf("[%s] %s [%s] %s", timestamp, level, l.prefix, message)
	} else {
		log.Printf("[%s] %s %s", timestamp, level, message)
	}
}

// SetLogLevel changes the logging level
func (l *Logger) SetLogLevel(level string) {
	switch strings.ToLower(level) {
	case debugStr:
		l.level = DEBUG
	case infoStr:
		l.level = INFO
	case warnStr:
		l.level = WARN
	case errorStr:
		l.level = ERROR
	}
}

// GetLogLevel returns the current log level as a string
func (l *Logger) GetLogLevel() string {
	switch l.level {
	case DEBUG:
		return "debug"
	case INFO:
		return "info"
	case WARN:
		return "warn"
	case ERROR:
		return "error"
	default:
		return "info"
	}
}
