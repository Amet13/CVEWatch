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

// Package cache provides caching functionality for CVEWatch.
//
// It implements a file-based cache with TTL support for storing
// API responses and reducing unnecessary network requests.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CacheEntry represents a cached item with expiration
type CacheEntry struct {
	Data      json.RawMessage `json:"data"`
	ExpiresAt time.Time       `json:"expires_at"`
	CreatedAt time.Time       `json:"created_at"`
}

// FileCache implements a file-based cache with TTL
type FileCache struct {
	cacheDir string
	ttl      time.Duration
	mu       sync.RWMutex
	enabled  bool
}

// NewFileCache creates a new file-based cache
func NewFileCache(cacheDir string, ttl time.Duration) (*FileCache, error) {
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		cacheDir = filepath.Join(homeDir, ".cvewatch", "cache")
	}

	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &FileCache{
		cacheDir: cacheDir,
		ttl:      ttl,
		enabled:  true,
	}, nil
}

// SetEnabled enables or disables the cache
func (c *FileCache) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

// IsEnabled returns whether the cache is enabled
func (c *FileCache) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// Get retrieves a cached entry by key
func (c *FileCache) Get(key string) (json.RawMessage, bool) {
	if !c.IsEnabled() {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	filePath := c.keyToPath(key)
	data, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		// Clean up expired entry asynchronously
		go func() {
			_ = c.Delete(key)
		}()
		return nil, false
	}

	return entry.Data, true
}

// Set stores a value in the cache
func (c *FileCache) Set(key string, value interface{}) error {
	if !c.IsEnabled() {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal cache value: %w", err)
	}

	entry := CacheEntry{
		Data:      data,
		ExpiresAt: time.Now().Add(c.ttl),
		CreatedAt: time.Now(),
	}

	entryData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	filePath := c.keyToPath(key)
	if err := os.WriteFile(filePath, entryData, 0600); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// Delete removes an entry from the cache
func (c *FileCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	filePath := c.keyToPath(key)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete cache file: %w", err)
	}

	return nil
}

// Clear removes all entries from the cache
func (c *FileCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(c.cacheDir, entry.Name())
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove cache file %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// CleanExpired removes all expired entries from the cache
func (c *FileCache) CleanExpired() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(c.cacheDir, entry.Name())
		data, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			continue
		}

		var cacheEntry CacheEntry
		if err := json.Unmarshal(data, &cacheEntry); err != nil {
			// Remove corrupted entries
			_ = os.Remove(filePath)
			continue
		}

		if time.Now().After(cacheEntry.ExpiresAt) {
			_ = os.Remove(filePath)
		}
	}

	return nil
}

// Stats returns cache statistics
func (c *FileCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := map[string]interface{}{
		"cache_dir": c.cacheDir,
		"ttl":       c.ttl.String(),
		"enabled":   c.enabled,
	}

	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		stats["error"] = err.Error()
		return stats
	}

	totalSize := int64(0)
	validCount := 0
	expiredCount := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		totalSize += info.Size()

		filePath := filepath.Join(c.cacheDir, entry.Name())
		data, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			continue
		}

		var cacheEntry CacheEntry
		if err := json.Unmarshal(data, &cacheEntry); err != nil {
			continue
		}

		if time.Now().After(cacheEntry.ExpiresAt) {
			expiredCount++
		} else {
			validCount++
		}
	}

	stats["total_entries"] = validCount + expiredCount
	stats["valid_entries"] = validCount
	stats["expired_entries"] = expiredCount
	stats["total_size_bytes"] = totalSize

	return stats
}

// keyToPath converts a cache key to a file path
func (c *FileCache) keyToPath(key string) string {
	hash := sha256.Sum256([]byte(key))
	filename := hex.EncodeToString(hash[:]) + ".json"
	return filepath.Join(c.cacheDir, filename)
}

// GenerateCacheKey generates a cache key from search parameters
func GenerateCacheKey(prefix string, params ...interface{}) string {
	key := prefix
	for _, param := range params {
		key += fmt.Sprintf(":%v", param)
	}
	return key
}
