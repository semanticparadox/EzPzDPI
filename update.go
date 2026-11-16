package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const flowsealLatestAPI = "https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest"

var updateClient = &http.Client{Timeout: 3 * time.Minute}

// latestFlowseal returns the newest Flowseal release tag and its .zip URL.
func latestFlowseal(ctx context.Context) (tag, zipURL string, err error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, flowsealLatestAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", appName+"/"+version)
	resp, err := updateClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	var rel struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return "", "", err
	}
	for _, a := range rel.Assets {
		if strings.HasSuffix(strings.ToLower(a.Name), ".zip") {
			return rel.Tag, a.URL, nil
		}
	}
	return "", "", errors.New("в релизе Flowseal нет .zip архива")
}

func downloadBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", appName+"/"+version)
	resp, err := updateClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("загрузка: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("архив слишком большой")
	}
	return data, nil
}

// installFlowsealZip validates a Flowseal release archive and installs its
// bin/, lists/ and general*.bat files into zapretDir. User lists stay intact.
// It returns the number of strategies installed.
func installFlowsealZip(data []byte, zapretDir string) (int, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, err
	}
	root, found := "", false
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "bin/winws.exe") {
			root, found = strings.TrimSuffix(f.Name, "bin/winws.exe"), true
			break
		}
	}
	if !found {
		return 0, errors.New("в архиве нет bin/winws.exe")
	}
	isStrategy := func(rel string) bool {
		return !strings.Contains(rel, "/") && strings.HasPrefix(strings.ToLower(rel), "general") &&
			strings.HasSuffix(strings.ToLower(rel), ".bat")
	}
	count := 0
	for _, f := range zr.File {
		rel, ok := strings.CutPrefix(f.Name, root)
		if !ok || !isStrategy(rel) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		src, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if _, err := parseFlowsealBat(string(src), `C:\b`, `C:\l`); err == nil {
			count++
		}
	}
	if count == 0 {
		return 0, errors.New("в архиве нет рабочих стратегий general*.bat")
	}
	// Build the new tree next to the old one and swap folders, so a failed
	// extraction never leaves a half-updated install.
	newDir, oldDir := zapretDir+".new", zapretDir+".old"
	_ = os.RemoveAll(newDir)
	_ = os.RemoveAll(oldDir)
	err = extractZip(zr, newDir, func(name string) (string, bool) {
		rel, ok := strings.CutPrefix(name, root)
		if !ok {
			return "", false
		}
		switch {
		case isStrategy(rel):
			return "strategies/" + rel, true
		case strings.HasPrefix(rel, "bin/") && !strings.Contains(rel[4:], "/"):
			return rel, true
		case strings.HasPrefix(rel, "lists/") && !strings.Contains(rel[6:], "/"):
			base := path.Base(rel)
			if strings.HasSuffix(base, "-user.txt") || strings.HasSuffix(base, ".backup") {
				return "", false
			}
			return rel, true
		}
		return "", false
	})
	if err != nil {
		_ = os.RemoveAll(newDir)
		return 0, err
	}
	if err := os.MkdirAll(filepath.Join(newDir, "lists"), 0o755); err != nil {
		_ = os.RemoveAll(newDir)
		return 0, err
	}
	for name := range userListDefaults {
		if data, err := os.ReadFile(filepath.Join(zapretDir, "lists", name)); err == nil {
			if err := os.WriteFile(filepath.Join(newDir, "lists", name), data, 0o644); err != nil {
				_ = os.RemoveAll(newDir)
				return 0, err
			}
		}
	}
	if err := ensureUserLists(filepath.Join(newDir, "lists")); err != nil {
		_ = os.RemoveAll(newDir)
		return 0, err
	}
	hadOld := false
	if _, err := os.Stat(zapretDir); err == nil {
		if err := os.Rename(zapretDir, oldDir); err != nil {
			_ = os.RemoveAll(newDir)
			return 0, fmt.Errorf("файлы заняты: %w", err)
		}
		hadOld = true
	}
	if err := os.Rename(newDir, zapretDir); err != nil {
		if hadOld {
			_ = os.Rename(oldDir, zapretDir)
		}
		_ = os.RemoveAll(newDir)
		return 0, err
	}
	_ = os.RemoveAll(oldDir)
	return count, nil
}
