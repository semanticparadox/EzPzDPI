package main

import (
	"regexp"
	"strings"
)

// engineErrorHints map Windows error codes that winws / GoodbyeDPI print
// when WinDivert cannot start to a plain explanation and a next step.
var engineErrorHints = map[string]string{
	"2":    "Не найден файл драйвера WinDivert. Скорее всего, его удалил антивирус: добавьте папку C:\\ProgramData\\EzPzDPI в исключения и откройте EzPzDPI снова.",
	"5":    "Доступ к драйверу WinDivert запрещён. Обычно это антивирус: добавьте папку C:\\ProgramData\\EzPzDPI в исключения.",
	"87":   "WinDivert не принял параметры. Обновите варианты обхода в настройках.",
	"577":  "Windows не принимает подпись драйвера WinDivert. Так бывает при включённой «Целостности памяти» или на старых сборках Windows 10 без обновлений. Установите обновления Windows; если не помогло, проверьте Безопасность Windows → Безопасность устройства → Изоляция ядра.",
	"654":  "Драйвер WinDivert другой версии уже загружен другой программой обхода. Закройте её или перезагрузите компьютер.",
	"1058": "Служба драйвера WinDivert отключена. Перезагрузите компьютер и попробуйте снова.",
	"1060": "Служба драйвера WinDivert не найдена. Перезагрузите компьютер и попробуйте снова.",
	"1275": "Windows заблокировала драйвер WinDivert. Это делает политика безопасности или антивирус: разрешите EzPzDPI в антивирусе или отключите блокировку уязвимых драйверов.",
	"1753": "Служба Windows, нужная драйверу, недоступна. Перезагрузите компьютер.",
}

var reErrCode = regexp.MustCompile(`(?i)(?:error|code|ошибка)[^0-9]{0,24}(\d{1,5})\b`)

// explainEngineLog turns the last line of an engine log into advice, or
// returns "" when the line has no known code.
func explainEngineLog(line string) string {
	l := strings.ToLower(line)
	if !strings.Contains(l, "windivert") && !strings.Contains(l, "error") && !strings.Contains(l, "ошибка") {
		return ""
	}
	if m := reErrCode.FindStringSubmatch(line); m != nil {
		if h, ok := engineErrorHints[m[1]]; ok {
			return h
		}
	}
	return ""
}
