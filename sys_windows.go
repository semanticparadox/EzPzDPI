//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const createNoWindow = 0x08000000

func initConsole(title string) {
	_ = windows.SetConsoleOutputCP(65001)
	_ = windows.SetConsoleCP(65001)
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	var mode uint32
	if err != nil || windows.GetConsoleMode(h, &mode) != nil ||
		windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		useColor = false
		return
	}
	os.Stdout.WriteString("\x1b]0;" + title + "\x07")
}

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// relaunchElevated restarts this exe through the UAC prompt.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_NORMAL)
}

func defaultDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, appName)
}

// dataDirSDDL: full control for SYSTEM and Administrators, read+execute for
// Users, no inheritance from C:\ProgramData (where Users may create files).
const dataDirSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// secureDataDir guarantees the data dir is a real folder owned by
// Administrators, SYSTEM or the current admin user before anything in it is
// read. A folder pre-created by someone else (for example to plant an exe
// for the LocalSystem service) is moved aside and replaced.
func secureDataDir(dir string) error {
	fi, err := os.Lstat(dir)
	switch {
	case err == nil && fi.IsDir() && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 && trustedOwner(dir):
		hardenDir(dir)
		return nil
	case err == nil:
		aside := fmt.Sprintf("%s.untrusted-%d", dir, time.Now().Unix())
		if err := os.Rename(dir, aside); err != nil {
			return fmt.Errorf("папку %s создал не администратор, и её не удалось убрать: %w", dir, err)
		}
		say(col(cYellow, "Папку %s создал не администратор: она перенесена в %s."), dir, aside)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return nil
}

func trustedOwner(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	if owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && windows.EqualSid(owner, tu.User.Sid)
}

// enableDebugPrivilege lets an elevated admin terminate LocalSystem
// processes, e.g. a winws service that does not stop in time.
func enableDebugPrivilege() {
	var tok windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok) != nil {
		return
	}
	defer tok.Close()
	name, _ := windows.UTF16PtrFromString("SeDebugPrivilege")
	var luid windows.LUID
	if windows.LookupPrivilegeValue(nil, name, &luid) != nil {
		return
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// hardenDir limits write access to SYSTEM and Administrators: a LocalSystem
// service runs winws.exe from this folder, so ordinary users must not be
// able to replace it. SIDs keep this independent of the Windows language.
func hardenDir(dir string) {
	run := func(args ...string) {
		cmd := exec.Command("icacls.exe", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		_ = cmd.Run()
	}
	run(dir, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q")
	run(dir, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX",
		"/C", "/Q")
	run(filepath.Join(dir, "*"), "/reset", "/T", "/C", "/Q")
}

type procInfo struct {
	PID  uint32
	Name string
	Path string
}

func listProcs(names ...string) []procInfo {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []procInfo
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		name := windows.UTF16ToString(pe.ExeFile[:])
		for _, n := range names {
			if strings.EqualFold(name, n) {
				out = append(out, procInfo{PID: pe.ProcessID, Name: name, Path: procPath(pe.ProcessID)})
			}
		}
	}
	return out
}

func procPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func killPID(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	_, _ = windows.WaitForSingleObject(h, 5000)
	return nil
}

var trialJob windows.Handle

// tieToJob puts a process into a kill-on-close job object, so trial engines
// die with this app even if it crashes or the console window is closed.
func tieToJob(pid int) {
	if trialJob == 0 {
		job, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(job)
			return
		}
		trialJob = job
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_ = windows.AssignProcessToJobObject(trialJob, h)
}

// startEngine launches an engine hidden, with output in logPath. tied=true
// binds its lifetime to this app (trials); tied=false leaves it running.
func startEngine(exe string, args []string, logPath string, tied bool) (*exec.Cmd, <-chan error, error) {
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	logf, err := os.Create(logPath)
	if err == nil {
		cmd.Stdout = logf
		cmd.Stderr = logf
		defer logf.Close()
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	if tied {
		tieToJob(cmd.Process.Pid)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return cmd, done, nil
}

// serviceStatus reports whether a Windows service exists and is running.
func serviceStatus(name string) (exists, running bool) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return false, false
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return true, false
	}
	return true, st.State == svc.Running || st.State == svc.StartPending
}

const (
	svcMissing = iota
	svcStopped
	svcPending
	svcRunning
)

func serviceState(name string) int {
	m, err := mgr.Connect()
	if err != nil {
		return svcMissing
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return svcMissing
	}
	defer s.Close()
	st, err := s.Query()
	switch {
	case err != nil:
		return svcStopped
	case st.State == svc.Running:
		return svcRunning
	case st.State == svc.Stopped:
		return svcStopped
	}
	return svcPending
}

// stopAndDeleteService is a no-op when the service does not exist.
func stopAndDeleteService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		s.Close()
		return err
	}
	s.Close()
	// The service disappears only when every handle to it is closed (an open
	// services.msc keeps one). Wait so the next CreateService does not fail.
	for i := 0; i < 25; i++ {
		s2, err := m.OpenService(name)
		if err != nil {
			return nil
		}
		s2.Close()
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("служба %s ещё удаляется: закройте окно «Службы» (services.msc), если оно открыто", name)
}

// installService (re)creates an auto-start service that runs exe with args
// and restarts it after a crash.
func installService(name, display, desc, exe string, args []string) error {
	_ = stopAndDeleteService(name)
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	var s *mgr.Service
	for i := 0; i < 40; i++ {
		s, err = m.CreateService(name, exe, mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: display,
			Description: desc,
		}, args...)
		if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.NoAction},
	}, 24*60*60)
	return s.Start()
}
