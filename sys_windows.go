//go:build windows

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const createNoWindow = 0x08000000

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole = kernel32.NewProc("AttachConsole")
	procAllocConsole  = kernel32.NewProc("AllocConsole")
	procFreeConsole   = kernel32.NewProc("FreeConsole")
	procGetConsoleWnd = kernel32.NewProc("GetConsoleWindow")
)

// setupConsole gives this GUI-subsystem exe a console for command-line use:
// the parent's console when started from cmd/PowerShell, else a new one.
// It returns true when a new console window was created.
func setupConsole(title string) (fresh bool) { return attachConsole(title, false) }

// attachConsole: own=true always opens a separate console window (the
// interactive menu must not share the parent shell, which does not wait
// for a GUI-subsystem program and would read the same input).
func attachConsole(title string, own bool) (fresh bool) {
	if own {
		procFreeConsole.Call()
		procAllocConsole.Call()
		reopenStd()
		initConsole(title)
		return true
	}
	// Output already redirected to a pipe or file (scripts, WSL): keep it
	// and do not pop up a console window.
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && h != 0 && h != windows.InvalidHandle {
		if t, _ := windows.GetFileType(h); t == windows.FILE_TYPE_PIPE || t == windows.FILE_TYPE_DISK {
			useColor = false
			return false
		}
	}
	const attachParent = ^uintptr(0) // ATTACH_PARENT_PROCESS
	if r, _, _ := procAttachConsole.Call(attachParent); r == 0 {
		procAllocConsole.Call()
		fresh = true
	}
	reopenStd()
	initConsole(title)
	return fresh
}

func reopenStd() {
	if f, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
		os.Stdin = f
		stdin = bufio.NewReader(f)
	}
}

var (
	procGetConsoleOutputCP = kernel32.NewProc("GetConsoleOutputCP")
	procGetConsoleCP       = kernel32.NewProc("GetConsoleCP")
	savedConsole           *struct{ outCP, inCP, mode uint32 }
)

func initConsole(title string) {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	haveMode := windows.GetConsoleMode(h, &mode) == nil
	if savedConsole == nil && haveMode {
		// Remember the console's settings: when attached to the user's
		// cmd/PowerShell they must get them back on exit.
		out, _, _ := procGetConsoleOutputCP.Call()
		in, _, _ := procGetConsoleCP.Call()
		savedConsole = &struct{ outCP, inCP, mode uint32 }{uint32(out), uint32(in), mode}
	}
	_ = windows.SetConsoleOutputCP(65001)
	_ = windows.SetConsoleCP(65001)
	if !haveMode || windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		useColor = false
		return
	}
	os.Stdout.WriteString("\x1b]0;" + title + "\x07")
}

// restoreConsole puts back the code pages and mode initConsole changed.
func restoreConsole() {
	if savedConsole == nil {
		return
	}
	_ = windows.SetConsoleOutputCP(savedConsole.outCP)
	_ = windows.SetConsoleCP(savedConsole.inCP)
	_ = windows.SetConsoleMode(windows.Handle(os.Stdout.Fd()), savedConsole.mode)
}

// messageBox shows a native dialog; used when the window cannot be opened.
func messageBox(text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(appName)
	r, _ := windows.MessageBox(0, t, c, flags)
	return r
}

// scheduleRemoval deletes dir after this process exits; the running exe
// may live inside it (Start menu copy), so it cannot delete itself now.
// Everything else is removed immediately; a hidden PowerShell waits for our
// PID to exit, then removes the folder. As a last resort the exe is marked
// for deletion at the next reboot.
func scheduleRemoval(dir string) {
	self, _ := os.Executable()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if !strings.EqualFold(p, self) {
			_ = os.RemoveAll(p)
		}
	}
	if strings.HasPrefix(strings.ToLower(self), strings.ToLower(dir)+`\`) {
		if p, err := windows.UTF16PtrFromString(self); err == nil {
			_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
	}
	// dir is our fixed ASCII data path and the PID is a number: nothing in
	// the script comes from user input.
	if p, err := windows.UTF16PtrFromString(dir); err == nil {
		_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT) // removed at reboot once empty
	}
	script := fmt.Sprintf("Wait-Process -Id %d -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '%s' -Recurse -Force -ErrorAction SilentlyContinue",
		os.Getpid(), strings.ReplaceAll(dir, "'", "''"))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.Dir = os.Getenv("SystemRoot")                                                                    // not inside the folder being removed
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow | 0x00000008} // DETACHED_PROCESS
	_ = cmd.Start()
}

// windowsVersion returns "10.0.26200" style text for reports.
func windowsVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

const healTaskName = `EzPzDPI\Heal`

// createLogonTask registers a task that runs exe with args a minute after
// the current user signs in, elevated, also on battery power (the default
// schtasks settings skip laptops on battery).
func createLogonTask(name, exe string, args ...string) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	xml := logonTaskXML(tu.User.Sid.String(), exe, args)
	// Written into the admin-only data folder, not %TEMP%: an unelevated
	// process could swap a temp file before schtasks reads it.
	f, err := os.CreateTemp(defaultDataDir(), "task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(encodeUTF16LE(xml)); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return runHidden("schtasks.exe", "/Create", "/F", "/TN", name, "/XML", f.Name())
}

// encodeUTF16LE encodes s as UTF-16 LE with a BOM, the encoding schtasks expects.
func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, 2+2*len(u))
	buf[0], buf[1] = 0xFF, 0xFE
	for i, c := range u {
		buf[2+2*i], buf[3+2*i] = byte(c), byte(c>>8)
	}
	return buf
}

// logonTaskXML builds the Task Scheduler 1.2 definition, elements in the
// schema's order.
func logonTaskXML(sid, exe string, args []string) string {
	var argStr []string
	for _, a := range args {
		argStr = append(argStr, syscall.EscapeArg(a))
	}
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>EzPzDPI: проверка обхода после входа в Windows</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + sid + `</UserId><Delay>PT1M</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>` + sid + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEscape(exe) + `</Command><Arguments>` + xmlEscape(strings.Join(argStr, " ")) + `</Arguments></Exec></Actions>
</Task>`
	return xml
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func deleteTask(name string) error {
	if !taskExists(name) {
		return nil
	}
	return runHidden("schtasks.exe", "/Delete", "/F", "/TN", name)
}

func taskExists(name string) bool { return runHidden("schtasks.exe", "/Query", "/TN", name) == nil }

func runHidden(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", exe, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runHiddenOutput(exe string, args ...string) (string, error) {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	return string(out), err
}

// svcInfo describes another program's Windows service.
type svcInfo struct {
	Name      string
	Exists    bool
	Running   bool
	StartType uint32
	BinPath   string
}

func queryService(name string) svcInfo {
	info := svcInfo{Name: name}
	m, err := mgr.Connect()
	if err != nil {
		return info
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return info
	}
	defer s.Close()
	info.Exists = true
	if st, err := s.Query(); err == nil {
		info.Running = st.State == svc.Running || st.State == svc.StartPending
	}
	if c, err := s.Config(); err == nil {
		info.StartType = c.StartType
		info.BinPath = c.BinaryPathName
	}
	return info
}

// setServiceStart changes a service's start type and optionally starts it.
func setServiceStart(name string, start uint32, startNow bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return err
	}
	c.StartType = start
	if err := s.UpdateConfig(c); err != nil {
		return err
	}
	if startNow {
		return s.Start()
	}
	return nil
}

// stopService stops a service without deleting it.
func stopService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return err
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	for i := 0; i < 40; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("служба %s не остановилась", name)
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
	// The known-folder API, not %ProgramData%: environment variables of an
	// elevated process can be influenced by the user.
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, appName)
}

// dataDirSDDL: full control for SYSTEM and Administrators, read+execute for
// Users, no inheritance from C:\ProgramData (where Users may create files).
const dataDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

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
	err = windows.CreateDirectory(p, sa)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// Some tokens cannot assign the Administrators group as owner at
		// creation; hardenDir sets it right after.
		if sd2, err2 := windows.SecurityDescriptorFromString(dataDirSDDL[len("O:BA"):]); err2 == nil {
			sa.SecurityDescriptor = sd2
			err = windows.CreateDirectory(p, sa)
		}
	}
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	hardenDir(dir)
	return nil
}

// createAdminOnlyDir creates a new folder readable and writable only by
// SYSTEM and Administrators. It fails if the path already exists, so a
// folder (or junction) someone planted in advance is never reused.
func createAdminOnlyDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(p, sa)
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
	// Only Administrators or SYSTEM: a folder owned by any user account
	// (even this one, unelevated) may hold files planted for the service.
	return owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)
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
			StartType:        mgr.StartAutomatic,
			DelayedAutoStart: true, // start after the network stack is up
			DisplayName:      display,
			Description:      desc,
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
	// Restart three times with growing delays, then stop: an engine that
	// keeps crashing must not loop forever. Counters reset after a day.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
		{Type: mgr.NoAction},
	}, 24*60*60)
	return s.Start()
}
