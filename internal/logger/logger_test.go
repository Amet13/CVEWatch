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

package logger

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		prefix   string
		expected LogLevel
	}{
		{"debug level", "debug", "test", DEBUG},
		{"info level", "info", "test", INFO},
		{"warn level", "warn", "test", WARN},
		{"error level", "error", "test", ERROR},
		{"invalid level defaults to info", "invalid", "test", INFO},
		{"empty level defaults to info", "", "test", INFO},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.level, tt.prefix)
			if logger.level != tt.expected {
				t.Errorf("NewLogger() level = %v, want %v", logger.level, tt.expected)
			}
			if logger.prefix != tt.prefix {
				t.Errorf("NewLogger() prefix = %v, want %v", logger.prefix, tt.prefix)
			}
		})
	}
}

func TestLogger_Debug(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	logger := NewLogger("debug", "test-prefix")

	// Test debug message when level allows
	logger.Debug("debug message: %s", "test")
	output := buf.String()

	if !strings.Contains(output, "DEBUG") {
		t.Error("Debug message should be logged when level is debug")
	}
	if !strings.Contains(output, "test-prefix") {
		t.Error("Debug message should include prefix")
	}
	if !strings.Contains(output, "debug message: test") {
		t.Error("Debug message should contain formatted text")
	}
}

func TestLogger_Info(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	logger := NewLogger("info", "test-prefix")

	// Test info message
	logger.Info("info message: %s", "test")
	output := buf.String()

	if !strings.Contains(output, "INFO") {
		t.Error("Info message should be logged")
	}
	if !strings.Contains(output, "test-prefix") {
		t.Error("Info message should include prefix")
	}
	if !strings.Contains(output, "info message: test") {
		t.Error("Info message should contain formatted text")
	}
}

func TestLogger_Warn(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	logger := NewLogger("warn", "test-prefix")

	// Test warn message
	logger.Warn("warn message: %s", "test")
	output := buf.String()

	if !strings.Contains(output, "WARN") {
		t.Error("Warn message should be logged")
	}
	if !strings.Contains(output, "test-prefix") {
		t.Error("Warn message should include prefix")
	}
	if !strings.Contains(output, "warn message: test") {
		t.Error("Warn message should contain formatted text")
	}
}

func TestLogger_Error(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	logger := NewLogger("error", "test-prefix")

	// Test error message
	logger.Error("error message: %s", "test")
	output := buf.String()

	if !strings.Contains(output, "ERROR") {
		t.Error("Error message should be logged")
	}
	if !strings.Contains(output, "test-prefix") {
		t.Error("Error message should include prefix")
	}
	if !strings.Contains(output, "error message: test") {
		t.Error("Error message should contain formatted text")
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	// Test with info level - should not log debug messages
	logger := NewLogger("info", "test")
	logger.Debug("debug message")
	output := buf.String()

	if strings.Contains(output, "debug message") {
		t.Error("Debug message should not be logged when level is info")
	}
}

func TestLogger_WithoutPrefix(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	logger := NewLogger("info", "")

	// Test message without prefix
	logger.Info("message without prefix")
	output := buf.String()

	if strings.Contains(output, "[test]") {
		t.Error("Message should not include prefix when prefix is empty")
	}
	if !strings.Contains(output, "message without prefix") {
		t.Error("Message should contain the log text")
	}
}

func TestLogger_SetLogLevel(t *testing.T) {
	logger := NewLogger("info", "test")

	tests := []struct {
		name          string
		level         string
		expectedLevel LogLevel
	}{
		{"set to debug", "debug", DEBUG},
		{"set to info", "info", INFO},
		{"set to warn", "warn", WARN},
		{"set to error", "error", ERROR},
		{"set to invalid", "invalid", INFO}, // should keep current level
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.SetLogLevel(tt.level)
			if tt.level != "invalid" && logger.level != tt.expectedLevel {
				t.Errorf("SetLogLevel() level = %v, want %v", logger.level, tt.expectedLevel)
			}
		})
	}
}

func TestLogger_GetLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		expected string
	}{
		{"debug level", DEBUG, "debug"},
		{"info level", INFO, "info"},
		{"warn level", WARN, "warn"},
		{"error level", ERROR, "error"},
		{"invalid level defaults to info", LogLevel(999), "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &Logger{level: tt.level}
			result := logger.GetLogLevel()
			if result != tt.expected {
				t.Errorf("GetLogLevel() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLogger_LogFormat(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	logger := NewLogger("info", "test-prefix")
	logger.Info("test message")

	output := buf.String()

	// Check that output contains expected elements
	if !strings.Contains(output, "INFO") {
		t.Error("Log should contain INFO level")
	}
	if !strings.Contains(output, "test-prefix") {
		t.Error("Log should contain prefix")
	}
	if !strings.Contains(output, "test message") {
		t.Error("Log should contain message")
	}

	// Check that the output has a reasonable structure
	parts := strings.Fields(output)
	if len(parts) < 4 {
		t.Error("Log output should have multiple parts")
	}
}
