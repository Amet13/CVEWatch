/*
 * MIT License
 *
 * Copyright (c) 2025 CVEWatch Contributors
 */

package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewFileCache(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()

	cache, err := NewFileCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	if cache == nil {
		t.Fatal("Expected non-nil cache")
	}

	if !cache.IsEnabled() {
		t.Error("Expected cache to be enabled by default")
	}
}

func TestNewFileCache_DefaultDir(t *testing.T) {
	// Test with empty directory (should use default)
	cache, err := NewFileCache("", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache with default dir: %v", err)
	}

	if cache == nil {
		t.Fatal("Expected non-nil cache")
	}

	// Clean up the default cache directory
	homeDir, _ := os.UserHomeDir()
	defaultCacheDir := filepath.Join(homeDir, ".cvewatch", "cache")
	os.RemoveAll(defaultCacheDir)
}

func TestFileCache_SetGet(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewFileCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Test data
	testData := map[string]interface{}{
		"id":    "CVE-2024-0001",
		"score": 9.8,
	}

	// Set value
	err = cache.Set("test-key", testData)
	if err != nil {
		t.Fatalf("Failed to set cache value: %v", err)
	}

	// Get value
	data, ok := cache.Get("test-key")
	if !ok {
		t.Fatal("Expected to get cached value")
	}

	if data == nil {
		t.Fatal("Expected non-nil data")
	}
}

func TestFileCache_GetMiss(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewFileCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Try to get non-existent key
	_, ok := cache.Get("non-existent-key")
	if ok {
		t.Error("Expected cache miss for non-existent key")
	}
}

func TestFileCache_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewFileCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Set value
	err = cache.Set("test-key", "test-value")
	if err != nil {
		t.Fatalf("Failed to set cache value: %v", err)
	}

	// Delete value
	err = cache.Delete("test-key")
	if err != nil {
		t.Fatalf("Failed to delete cache value: %v", err)
	}

	// Verify it's gone
	_, ok := cache.Get("test-key")
	if ok {
		t.Error("Expected cache miss after delete")
	}
}

func TestFileCache_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewFileCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Set multiple values
	for i := 0; i < 5; i++ {
		key := "test-key-" + string(rune('a'+i))
		err = cache.Set(key, i)
		if err != nil {
			t.Fatalf("Failed to set cache value: %v", err)
		}
	}

	// Clear cache
	err = cache.Clear()
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Verify all gone
	for i := 0; i < 5; i++ {
		key := "test-key-" + string(rune('a'+i))
		_, ok := cache.Get(key)
		if ok {
			t.Errorf("Expected cache miss after clear for key %s", key)
		}
	}
}

func TestFileCache_Expiration(t *testing.T) {
	tmpDir := t.TempDir()
	// Create cache with very short TTL
	cache, err := NewFileCache(tmpDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Set value
	err = cache.Set("test-key", "test-value")
	if err != nil {
		t.Fatalf("Failed to set cache value: %v", err)
	}

	// Verify it exists
	_, ok := cache.Get("test-key")
	if !ok {
		t.Fatal("Expected to get cached value before expiration")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Verify it's expired
	_, ok = cache.Get("test-key")
	if ok {
		t.Error("Expected cache miss after expiration")
	}
}

func TestFileCache_SetEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewFileCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Disable cache
	cache.SetEnabled(false)

	if cache.IsEnabled() {
		t.Error("Expected cache to be disabled")
	}

	// Set value (should be no-op when disabled)
	err = cache.Set("test-key", "test-value")
	if err != nil {
		t.Errorf("Set should not error when disabled: %v", err)
	}

	// Get should return false
	_, ok := cache.Get("test-key")
	if ok {
		t.Error("Expected cache miss when disabled")
	}

	// Re-enable
	cache.SetEnabled(true)

	if !cache.IsEnabled() {
		t.Error("Expected cache to be enabled")
	}
}

func TestFileCache_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewFileCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Add some entries
	for i := 0; i < 3; i++ {
		key := "test-key-" + string(rune('a'+i))
		err = cache.Set(key, i)
		if err != nil {
			t.Fatalf("Failed to set cache value: %v", err)
		}
	}

	stats := cache.Stats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}

	totalEntries, ok := stats["total_entries"].(int)
	if !ok {
		t.Fatal("Expected total_entries to be int")
	}
	if totalEntries != 3 {
		t.Errorf("Expected 3 total entries, got %d", totalEntries)
	}

	validEntries, ok := stats["valid_entries"].(int)
	if !ok {
		t.Fatal("Expected valid_entries to be int")
	}
	if validEntries != 3 {
		t.Errorf("Expected 3 valid entries, got %d", validEntries)
	}
}

func TestFileCache_CleanExpired(t *testing.T) {
	tmpDir := t.TempDir()
	// Create cache with very short TTL
	cache, err := NewFileCache(tmpDir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create file cache: %v", err)
	}

	// Add entries
	for i := 0; i < 3; i++ {
		key := "test-key-" + string(rune('a'+i))
		err = cache.Set(key, i)
		if err != nil {
			t.Fatalf("Failed to set cache value: %v", err)
		}
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Clean expired
	err = cache.CleanExpired()
	if err != nil {
		t.Fatalf("Failed to clean expired entries: %v", err)
	}

	// Verify files are removed
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read cache dir: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", len(entries))
	}
}

func TestGenerateCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		params   []interface{}
		expected string
	}{
		{
			name:     "prefix only",
			prefix:   "search",
			params:   nil,
			expected: "search",
		},
		{
			name:     "with string param",
			prefix:   "search",
			params:   []interface{}{"openssl"},
			expected: "search:openssl",
		},
		{
			name:     "with multiple params",
			prefix:   "search",
			params:   []interface{}{"openssl", 7, 9.8},
			expected: "search:openssl:7:9.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateCacheKey(tt.prefix, tt.params...)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}
