package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// payload.zip is assembled by scripts/build.sh from pinned, checksummed
// upstream releases (Flowseal zapret-discord-youtube, GoodbyeDPI).
//
//go:embed assets/payload.zip
var payloadZip []byte

// PayloadInfo records which upstream versions are unpacked in the data dir.
type PayloadInfo struct {
	Flowseal   string `json:"flowseal"`
	GoodbyeDPI string `json:"goodbyedpi"`
	Source     string `json:"source,omitempty"`
}

func embeddedZip() (*zip.Reader, error) {
	return zip.NewReader(bytes.NewReader(payloadZip), int64(len(payloadZip)))
}

func readEmbeddedInfo() (PayloadInfo, error) {
	var info PayloadInfo
	zr, err := embeddedZip()
	if err != nil {
		return info, err
	}
	f, err := zr.Open("payload.json")
	if err != nil {
		return info, err
	}
	defer f.Close()
	err = json.NewDecoder(f).Decode(&info)
	return info, err
}

func readInstalledInfo(dataDir string) (PayloadInfo, error) {
	var info PayloadInfo
	data, err := os.ReadFile(filepath.Join(dataDir, "payload.json"))
	if err != nil {
		return info, err
	}
	err = json.Unmarshal(data, &info)
	return info, err
}

func writeInstalledInfo(dataDir string, info PayloadInfo) error {
	data, _ := json.MarshalIndent(info, "", "  ")
	return os.WriteFile(filepath.Join(dataDir, "payload.json"), data, 0o644)
}

// extractZip writes zip entries into dest. mapName returns the relative
// destination path for an entry, or false to skip it.
func extractZip(zr *zip.Reader, dest string, mapName func(string) (string, bool)) error {
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rel, ok := mapName(f.Name)
		if !ok {
			continue
		}
		target := filepath.Join(destAbs, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, destAbs+string(os.PathSeparator)) {
			return fmt.Errorf("недопустимый путь в архиве: %s", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := writeZipFile(f, target); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
	}
	return nil
}

func writeZipFile(f *zip.File, target string) error {
	// Skip identical files: a running engine may hold its exe/dll/driver open.
	if st, err := os.Stat(target); err == nil && uint64(st.Size()) == f.UncompressedSize64 {
		if same, _ := sameContent(f, target); same {
			return nil
		}
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(rc, 64<<20)); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func sameContent(f *zip.File, target string) (bool, error) {
	rc, err := f.Open()
	if err != nil {
		return false, err
	}
	defer rc.Close()
	want, err := io.ReadAll(io.LimitReader(rc, 64<<20))
	if err != nil {
		return false, err
	}
	have, err := os.ReadFile(target)
	if err != nil {
		return false, err
	}
	return bytes.Equal(want, have), nil
}

// userListDefaults mirrors Flowseal's load_user_lists: these files must
// exist (winws refuses missing lists) and are never overwritten.
var userListDefaults = map[string]string{
	"list-general-user.txt":  "# Свои сайты для обхода: по одному домену на строку\r\n# Never leave this file empty\r\ndomain.example.abc\r\n",
	"list-exclude-user.txt":  "domain.example.abc\r\n",
	"ipset-exclude-user.txt": "203.0.113.113/32\r\n",
}

func ensureUserLists(listsDir string) error {
	for name, content := range userListDefaults {
		p := filepath.Join(listsDir, name)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// versionLess compares dotted numeric versions such as "1.10.4".
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var out []int
	for _, p := range strings.Split(v, ".") {
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		n, _ := strconv.Atoi(p[:end])
		out = append(out, n)
	}
	return out
}
