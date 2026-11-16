<p align="center">
  <img src="docs/banner.svg" width="720" alt="EzPzDPI">
</p>

<p align="center">
  <b>Обход блокировок YouTube и Discord на Windows без ручного перебора bat-файлов.</b><br>
  Один portable-файл сам проверяет стратегии zapret и GoodbyeDPI у вашего провайдера и включает рабочую.
</p>

<p align="center">
  <a href="https://github.com/semanticparadox/EzPzDPI/releases/latest/download/EzPzDPI.exe"><img src="https://img.shields.io/badge/%D0%A1%D0%BA%D0%B0%D1%87%D0%B0%D1%82%D1%8C-EzPzDPI.exe-d0451b?style=for-the-badge&logo=windows&logoColor=white" alt="Скачать EzPzDPI.exe"></a>
</p>

<p align="center">
  <a href="https://github.com/semanticparadox/EzPzDPI/releases/latest"><img src="https://img.shields.io/github/v/release/semanticparadox/EzPzDPI?label=%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F" alt="Версия"></a>
  <a href="https://github.com/semanticparadox/EzPzDPI/releases"><img src="https://img.shields.io/github/downloads/semanticparadox/EzPzDPI/total?label=%D1%81%D0%BA%D0%B0%D1%87%D0%B8%D0%B2%D0%B0%D0%BD%D0%B8%D0%B9" alt="Скачиваний"></a>
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011%20x64-0078d4" alt="Windows 10 | 11 x64">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/semanticparadox/EzPzDPI?label=%D0%BB%D0%B8%D1%86%D0%B5%D0%BD%D0%B7%D0%B8%D1%8F" alt="Лицензия"></a>
</p>

---

## Зачем это

Обычный путь с [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube): скачать архив, по очереди запускать `general.bat`, `general (ALT).bat`, …, `general (ALT13).bat` и каждый раз вручную проверять, открылись ли YouTube и Discord. У каждого провайдера работает своя стратегия, а после очередного обновления блокировок поиск начинается заново.

EzPzDPI делает этот перебор сам. Он запускает стратегии по одной, проверяет, что YouTube и Discord действительно загружаются, и включает лучшую. На всё уходит от одной до четырёх минут.

## Установка

1. Скачайте [**EzPzDPI.exe**](https://github.com/semanticparadox/EzPzDPI/releases/latest/download/EzPzDPI.exe). Установка не нужна: это один файл.
2. Запустите его. Windows попросит права администратора: без них драйвер перехвата трафика WinDivert не запустится.
3. Если появится окно «Система Windows защитила ваш компьютер», нажмите «Подробнее», затем «Выполнить в любом случае». Файл не подписан платным сертификатом, поэтому SmartScreen его не знает.
4. В меню нажмите **1** («Автоподбор и включение»).
5. Когда подбор закончится, выберите «Включить и запускать вместе с Windows». После этого окно можно закрыть.

Если Discord был открыт, полностью закройте его через значок в трее и запустите снова.

## Как это выглядит

```
  EzPzDPI 0.1.0  обход блокировок YouTube и Discord
  Стратегии: Flowseal 1.10.4 (25 шт.) + GoodbyeDPI
  Обход: выключен

  1. Автоподбор и включение (рекомендуется)
  2. Включить сохранённую стратегию
  3. Выбрать стратегию вручную
  4. Проверить, открываются ли YouTube и Discord
  5. Выключить обход
  6. Полный подбор (проверить все стратегии и выбрать самую быструю)
  7. Обновить стратегии с GitHub (Flowseal)
  8. Удалить всё (службу и рабочие файлы)
  0. Выход
```

## Как это работает

- **Что внутри.** `winws.exe` из [zapret](https://github.com/bol-van/zapret), 22 стратегии из [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) 1.10.4 вместе с их списками доменов и fake-пакетами, плюс три пресета [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) 0.2.3rc3 как запасной вариант.
- **Куда распаковывается.** В `C:\ProgramData\EzPzDPI`. Путь без кириллицы и пробелов (winws с ними работает плохо), запись в папку разрешена только администраторам: из неё запускается служба.
- **Как проверяется стратегия.** EzPzDPI запускает её и открывает `www.youtube.com`, `i.ytimg.com`, `redirector.googlevideo.com`, `discord.com`, `gateway.discord.gg`, `cdn.discordapp.com` и `updates.discord.com`. Соединение устанавливается с TLS-отпечатком Chrome, поэтому DPI провайдера видит то же, что при работе браузера. Проверка считается пройденной, только если страница реально скачалась: с YouTube не меньше 128 КБ, с Discord не меньше 64 КБ. Так ловится не только полная блокировка, но и замедление, и «заморозка» соединения после 16–20 КБ.
- **Выбор.** Быстрый подбор останавливается на первой стратегии, которая прошла все проверки два раза подряд. Полный подбор проверяет все стратегии и берёт самую быструю из подтверждённых.
- **Включение.** Стратегия запускается как служба Windows `EzPzDPI` с автозапуском и перезапуском при сбое, или только до перезагрузки.
- **Обновления.** Пункт 7 скачивает последний релиз Flowseal с GitHub и подхватывает новые стратегии. Ваши списки `list-general-user.txt` и `list-exclude-user.txt` при этом не трогаются.
- **Другие обходы.** Если уже запущены zapret, GoodbyeDPI или их службы, EzPzDPI предложит их остановить: две программы на WinDivert одновременно мешают друг другу.

## Свои сайты

Добавьте домены по одному на строку в `C:\ProgramData\EzPzDPI\zapret\lists\list-general-user.txt` (файл открывается от имени администратора), затем снова включите стратегию через пункт 2.

## Командная строка

```
EzPzDPI.exe -auto    подобрать стратегию и включить её службой
EzPzDPI.exe -run     включить сохранённую стратегию
EzPzDPI.exe -stop    выключить обход
EzPzDPI.exe -check   проверить, открываются ли YouTube и Discord
```

## Если не работает

- **Антивирус удалил файлы.** WinDivert и winws часто помечаются как HackTool или RiskWare: это драйвер перехвата сетевых пакетов, и антивирусы реагируют на сам класс программ. Добавьте `C:\ProgramData\EzPzDPI` в исключения и запустите EzPzDPI снова.
- **Включён VPN или прокси.** Выключите их на время подбора.
- **Провайдер подменяет DNS.** EzPzDPI сообщит об этом при проверке. Включите «Безопасный DNS» в браузере: Chrome, Edge или Яндекс Браузер → Настройки → Конфиденциальность → Использовать безопасный DNS → Cloudflare или Google.
- **YouTube в Chrome всё равно тормозит.** Откройте `chrome://flags/#enable-quic`, выберите Disabled и перезапустите браузер.
- **Голосовые каналы Discord.** Стратегии включают обход для UDP, но автопроверка их не тестирует. Если голос не подключается, попробуйте соседнюю стратегию через пункт 3.
- **Ни одна стратегия не помогла.** Обновите стратегии (пункт 7) и повторите подбор. Если и это не помогло, провайдер блокирует по IP-адресам, и тогда поможет только VPN.

Лог последнего запуска движка: `C:\ProgramData\EzPzDPI\logs\engine.log`.

## Удаление

Пункт 8 в меню удаляет службу и папку `C:\ProgramData\EzPzDPI`. После этого удалите сам `EzPzDPI.exe`.

## Статус

Это первая версия. Сборка, разбор всех стратегий (`winws --dry-run`) и сетевые проверки протестированы на Windows 11. Работа у конкретных российских провайдеров зависит от их оборудования: напишите в [Issues](https://github.com/semanticparadox/EzPzDPI/issues), какой у вас провайдер и какая стратегия подобралась.

## Сборка из исходников

Нужны Linux, macOS или WSL, Go (версия в `go.mod`), `curl`, `unzip` и `python3`:

```bash
scripts/build.sh
```

Скрипт скачивает закреплённые релизы Flowseal и GoodbyeDPI, сверяет их SHA-256, собирает архив и кросс-компилирует `dist/EzPzDPI.exe`.

## Благодарности и лицензии

EzPzDPI только автоматизирует выбор. Сам обход DPI делают [zapret](https://github.com/bol-van/zapret) (bol-van), стратегии и списки поддерживает [Flowseal](https://github.com/Flowseal/zapret-discord-youtube), запасной движок — [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) (ValdikSS), перехват пакетов — [WinDivert](https://github.com/basil00/WinDivert) (basil00). Лицензии компонентов перечислены в [THIRD-PARTY.md](THIRD-PARTY.md). Код EzPzDPI распространяется по лицензии [MIT](LICENSE).

---

### English

EzPzDPI is a single portable Windows executable that picks a working DPI-bypass strategy for YouTube and Discord automatically. It bundles zapret's `winws.exe` with the Flowseal strategy set and GoodbyeDPI as a fallback, runs each strategy, verifies that YouTube and Discord actually load (Chrome TLS fingerprint, minimum download size to catch throttling and the 16–20 KB freeze), and installs the best one as an auto-start Windows service. Download the latest `EzPzDPI.exe` from [Releases](https://github.com/semanticparadox/EzPzDPI/releases/latest), run it as administrator and press 1.
