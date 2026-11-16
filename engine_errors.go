package main

import (
	"regexp"
	"strconv"
	"strings"
)

// X01: winws and GoodbyeDPI stop with a Windows error when WinDivert cannot
// start. The engines print it differently:
//
//	winws:      "windivert: error opening filter: <English system message>"
//	            plus "windivert: try to disable secure boot and install OS patches" on 577
//	            or "win_dark_init failed. win32 error 1753 (0x000006D9)"
//	GoodbyeDPI: "Error opening filter: 577 <English system message>"
//
// Both call FormatMessage with LANG_ENGLISH, so the message text is stable
// and can be matched on any Windows display language.

// Windows error codes that matter for the packet driver.
const (
	errFileNotFound      = 2
	errAccessDenied      = 5
	errInvalidParameter  = 87
	errVirusInfected     = 225
	errInvalidImageHash  = 577
	errDriverPriorUnload = 654
	errServiceDisabled   = 1058
	errServiceMissing    = 1060
	errServiceDeleting   = 1072
	errDriverBlocked     = 1275
	errNoEndpoints       = 1753
	errPolicyBlocked     = 4551
)

// engineCodeEAC marks the Easy Anti-Cheat message about a stale driver; it
// is not a Windows code, so it lives outside the Windows range.
const engineCodeEAC = -1

const avFolderHint = "Добавьте папку C:\\ProgramData\\EzPzDPI в исключения антивируса и откройте EzPzDPI снова — файлы восстановятся."

// engineErrorHints is plain Russian advice per code. Causes reported by the
// community rather than documented by WinDivert say "вероятно".
var engineErrorHints = map[int]string{
	errFileNotFound: "Не найден файл сетевого драйвера WinDivert. Вероятно, его удалил антивирус. " + avFolderHint,
	errAccessDenied: "Нет доступа к сетевому драйверу WinDivert. Откройте EzPzDPI от имени администратора. " +
		"Если не помогло, вероятно, драйвер блокирует антивирус. " + avFolderHint,
	errInvalidParameter: "Сетевой драйвер не принял настройки этого варианта обхода. Выберите другой вариант или обновите варианты обхода в настройках.",
	errVirusInfected: "Антивирус заблокировал файл обхода. Это частая ложная тревога: драйвер меняет сетевые пакеты, поэтому антивирусы его не любят. " +
		avFolderHint,
	errInvalidImageHash: "Windows не принимает подпись сетевого драйвера WinDivert. Так бывает на Windows 10 без обновлений " +
		"или при включённой «Целостности памяти». Установите все обновления Windows и попробуйте снова. " +
		"Сама программа обхода советует отключить Secure Boot, но мы этого не рекомендуем: это снижает защиту компьютера.",
	errDriverPriorUnload: "Уже загружен сетевой драйвер WinDivert другой версии — его держит другая программа обхода. " +
		"Закройте её или нажмите «Заменить на EzPzDPI»; если не помогло, перезагрузите компьютер.",
	errServiceDisabled: "Служба сетевого драйвера WinDivert отключена. Перезагрузите компьютер и попробуйте снова.",
	errServiceMissing:  "Служба сетевого драйвера WinDivert не найдена. Перезагрузите компьютер и попробуйте снова.",
	errServiceDeleting: "Старая служба сетевого драйвера ещё удаляется и ждёт перезагрузки. Перезагрузите компьютер и попробуйте снова.",
	errDriverBlocked: "Windows заблокировала загрузку сетевого драйвера WinDivert. Вероятно, это «Целостность памяти», " +
		"блокировка уязвимых драйверов или антивирус. Установите обновления Windows и разрешите EzPzDPI в антивирусе. " +
		"Отключать защиту Windows — только ваше решение: это снижает безопасность компьютера.",
	errNoEndpoints: "Не работает служба Windows «Служба базовой фильтрации» (BFE), без неё сетевой драйвер не запускается. " +
		"Включите её кнопкой в уведомлении EzPzDPI или перезагрузите компьютер.",
	errPolicyBlocked: "Политика безопасности Windows («Интеллектуальное управление приложениями» или правила организации) " +
		"запретила запуск файла обхода. На этом компьютере EzPzDPI работать не сможет, пока политика включена.",
	engineCodeEAC: "Античит Easy Anti-Cheat видит старый сетевой драйвер, файл которого уже удалён. " +
		"Перезагрузите компьютер — драйвер выгрузится, игра запустится.",
}

// winMessageCodes maps the English FormatMessage text (lower case, enough
// of it to be unique) back to the code, for winws which prints only text.
var winMessageCodes = []struct {
	text string
	code int
}{
	{"cannot find the file specified", errFileNotFound},
	{"access is denied", errAccessDenied},
	{"the parameter is incorrect", errInvalidParameter},
	{"contains a virus or potentially unwanted software", errVirusInfected},
	{"cannot verify the digital signature", errInvalidImageHash},
	{"previous version of the driver is still in memory", errDriverPriorUnload},
	{"either because it is disabled", errServiceDisabled},
	{"does not exist as an installed service", errServiceMissing},
	{"has been marked for deletion", errServiceDeleting},
	{"driver has been blocked from loading", errDriverBlocked},
	{"no more endpoints available from the endpoint mapper", errNoEndpoints},
	{"application control policy has blocked this file", errPolicyBlocked},
}

var (
	// GoodbyeDPI prints the number right after the colon.
	reFilterCode = regexp.MustCompile(`(?i)error opening filter:\s*(\d{1,5})\b`)
	// winws prints the number when its startup (win_dark_init) fails.
	reWin32Code = regexp.MustCompile(`(?i)win32 error\s+(\d{1,5})\b`)
	// Last resort for other wording: a known code near "error"/"ошибка".
	reErrCode = regexp.MustCompile(`(?i)(?:error|code|ошибка)[^0-9]{0,24}(\d{1,5})\b`)
)

// engineLogCode extracts the Windows error code from engine output. It
// accepts a single line or a whole log and reports the first known code,
// scanning from the end because the failure is the last thing an engine
// writes. ok is false when no known code is found.
func engineLogCode(log string) (code int, ok bool) {
	lines := strings.Split(strings.ReplaceAll(log, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if c, ok := lineCode(lines[i]); ok {
			return c, true
		}
	}
	return 0, false
}

// lineCode recognises one line; the most specific patterns go first.
func lineCode(line string) (int, bool) {
	l := strings.ToLower(strings.TrimSpace(line))
	switch {
	case l == "":
		return 0, false
	case strings.Contains(l, "is loaded but its file is missing"):
		return engineCodeEAC, true
	case strings.Contains(l, "try to disable secure boot"):
		return errInvalidImageHash, true
	}
	for _, re := range []*regexp.Regexp{reFilterCode, reWin32Code} {
		if c, ok := knownCode(re.FindStringSubmatch(l)); ok {
			return c, true
		}
	}
	if strings.Contains(l, "error opening filter") || strings.Contains(l, "windivert") {
		for _, m := range winMessageCodes {
			if strings.Contains(l, m.text) {
				return m.code, true
			}
		}
	}
	if strings.Contains(l, "windivert") || strings.Contains(l, "error") || strings.Contains(l, "ошибка") {
		return knownCode(reErrCode.FindStringSubmatch(l))
	}
	return 0, false
}

// knownCode turns a regexp match into a code we have advice for.
func knownCode(m []string) (int, bool) {
	if m == nil {
		return 0, false
	}
	c, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	_, ok := engineErrorHints[c]
	return c, ok
}

// explainEngineLog turns engine output (usually its last line) into plain
// Russian advice, or returns "" when it has no known error.
func explainEngineLog(line string) string {
	if c, ok := engineLogCode(line); ok {
		return engineErrorHints[c]
	}
	return ""
}
