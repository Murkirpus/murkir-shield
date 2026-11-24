# MurKir Shield

## Щит MurKir — заблокированные IP
Пример работы с блокировкой по API
https://murkir.com/blocked-ips
https://murkir.com/avtozashchita-v-realnom-vremeni-demon-php-83

**Живые логи nginx и автозащита от ботов в реальном времени на чистом PHP: без JS-проверок, без Composer, без Redis.**

> **EN:** Real-time nginx log viewer and auto-ban daemon in plain PHP 8.3. A single-file web panel (`logs.php`) shows live traffic, bots, SEO crawl stats and threats. A systemd daemon (`shield-daemon.php`) applies 15 detection rules within a second and bans IPs through your firewall API. It has no JavaScript challenge, so search engines are never blocked: Googlebot and Bingbot are verified by rDNS and by their official IP ranges.

---

Баны выполняются на уровне ядра через **[murkir-ipset-api](https://github.com/Murkirpus/murkir-ipset-api)**: ipset или nftables, автоматический разбан по таймауту, без cron.

## Зачем

Обычная автозащита по cron разбирает логи раз в минуту, и у агрессивного бота есть до 60 секунд, чтобы положить сайт. JS-проверки решают эту проблему, но мешают поисковикам.

MurKir Shield читает логи непрерывно и банит нарушителя **меньше чем за секунду**. При этом настоящие Googlebot, Bingbot и Яндекс не страдают.

## Что внутри

| Файл | Что это |
|---|---|
| `logs.php` | Веб-панель в одном файле: живая лента запросов, аналитика, SEO, посетители, угрозы, ручная блокировка и настройки автозащиты |
| `shield-daemon.php` | Демон для systemd: читает логи в реальном времени и применяет правила из `logs.php` |
| `systemd/murkir-shield.service` | Юнит systemd |

### Панель `logs.php`
- Находит access-логи сама: nginx, Apache, ISPmanager, FastPanel и др. Понимает форматы combined, main и JSON.
- Делит трафик на людей, поисковиков, ИИ-ботов и прочих ботов. Поддельных поисковиков находит по rDNS.
- Вкладки: лента, обзор, аналитика (скорость, тепловая карта, трафик), SEO (обход роботами, потерянный краулинговый бюджет), визиты, медленные страницы, угрозы, блокировка, автозащита.
- Блокирует IP и подсети через ваш API, генерирует конфиг nginx (`deny`, `map` по User-Agent), выгружает CSV.

### Автозащита: 15 правил
Атака на сайт (SQLi, XSS, LFI, RCE, Log4Shell) · сканер уязвимостей · зондирование сервера · подбор пароля · вредный бот · поддельный поисковик · флуд · спам формами · агрессивный парсер · перебор адресов (404) · ломится в закрытое (403/429/444) · без User-Agent · смена масок · сумма слабых признаков · атака подсетью (/24, /64).

Пороги и сроки меняются прямо на странице. Повторным нарушителям срок удваивается (до 30 дней), предохранитель не даёт сделать больше 60 банов в час. Есть режим «Наблюдение», в котором автозащита только записывает в журнал, кого заблокировала бы.

### Демон `shield-daemon.php`
- Читает все найденные логи каждые 0,25 с, как `tail -F`: ротацию и copytruncate отрабатывает, смещения сохраняет, после рестарта строки не теряются.
- Применяет правила каждые 0,5 с к IP с новыми запросами.
- Главный цикл никогда не ждёт сеть: баны выполняет дочерний процесс `ban`, проверки rDNS — процесс `rdns`.
- Раз в сутки скачивает официальные диапазоны IP Googlebot и Bingbot. IP из них не банятся никаким правилом.
- Пока демон работает, проверка из cron и со страницы автоматически пропускается, двойных банов не будет.
- Состояние хранится в том же формате, что у `logs.php`, поэтому демон можно остановить, и cron продолжит с того же места.
- В покое занимает 15–30 МБ, ограничен `MemoryMax=128M`.

## Требования
- PHP 8.3 CLI с расширениями `pcntl`, `posix`, `curl`, `mbstring`
- Linux с systemd, nginx (или Apache)
- API блокировки IP. Рекомендуется [murkir-ipset-api](https://github.com/Murkirpus/murkir-ipset-api) (см. ниже). Без API панель работает, а автозащита — только в режиме «Наблюдение».

## Установка

1. Положите `logs.php` и `shield-daemon.php` в одну папку сайта, например `/var/www/example.com`.
2. Откройте `logs.php` и задайте в начале файла:
   ```php
   const AUTH_PASS     = 'ваш-пароль';
   const BLOCK_API_URL = 'https://example.com/API/iptables.php';
   const BLOCK_API_KEY = 'ваш-ключ';
   ```
3. Проверьте, что PHP читает логи: откройте `https://example.com/logs.php`. Если доступа нет, панель сама подскажет команды.
4. Поставьте сервис: поправьте в `systemd/murkir-shield.service` пути и пользователя (тот же, что у PHP-FPM) и выполните:
   ```bash
   cp systemd/murkir-shield.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now murkir-shield
   systemctl status murkir-shield --no-pager
   ```
5. Первые сутки держите режим «👁 Наблюдение» (вкладка «🤖 Автозащита»), посмотрите журнал, затем включите «⛔ Блокирует».

Журнал демона: `journalctl -u murkir-shield -f`. Перечитать настройки: `systemctl reload murkir-shield`.

Без демона автозащиту можно запускать из cron раз в минуту: готовая строка есть на вкладке «Автозащита».

## API блокировки: murkir-ipset-api

MurKir Shield сделан в паре с **[murkir-ipset-api](https://github.com/Murkirpus/murkir-ipset-api)**. Это API и веб-интерфейс в одном PHP-файле, которые блокируют IPv4/IPv6 и подсети через `ipset` (`iptables.php`) или `nftables` (`nftables.php`). Ядро проверяет пакеты по хэш-таблице за O(1) и само снимает бан, когда истекает срок: cron и скрипты очистки не нужны.

Как подключить:
1. Установите murkir-ipset-api по его инструкции. Лучше на отдельном субдомене и отдельной версии PHP с разрешённым `exec`.
2. В его `settings.php` задайте ключ `API_BLOCK_KEY` (`openssl rand -hex 24`) и добавьте в `$IP_WHITELIST` IP своего сервера.
3. В начале `logs.php` укажите адрес и тот же ключ:
   ```php
   const BLOCK_API_URL = 'https://dos.example.com/iptables.php';   // или nftables.php
   const BLOCK_API_KEY = 'тот-же-ключ-что-в-settings.php';
   ```
4. Откройте `logs.php`, вкладку «🚫 Блокировка»: там должен появиться список «Сейчас в iptables». Если список загрузился, связка работает.

Что используется из API: `block` (с `timeout`), `unblock`, `list` и `clear`. Срок бана выбирает автозащита, а снимает его ядро. Белый список murkir-ipset-api работает как вторая страховка: IP из него не заблокирует ни панель, ни демон.

### Свой API

Подойдёт и любая другая обёртка над `ipset`/`iptables`/`nftables` с таким же протоколом. `logs.php` и демон отправляют POST-запрос на `BLOCK_API_URL` с полями:

| Поле | Значение |
|---|---|
| `action` | `block`, `unblock`, `list`, `clear` |
| `api_key` | ключ из `BLOCK_API_KEY` |
| `ip` | IP или подсеть (`1.2.3.4`, `1.2.3.0/24`, `2a03::/64`) |
| `timeout` | срок бана в секундах (для `block`) |

Ответ считается успешным при HTTP 2xx и JSON с `success`/`ok`/`status`, равным `true`, `ok`, `success` или `blocked`. На `list` можно вернуть JSON любой формы с IP (поля `ip`, `expires`, `comment` распознаются) или просто текст со списком адресов.

## Рекомендуется для nginx

Лимит параллельных запросов к PHP. Зона одна на все сайты, в `http {}`:
```nginx
limit_conn_zone $binary_remote_addr zone=perip:10m;
```
В `location ~ \.php$` каждого сайта (статику не ограничивайте):
```nginx
limit_conn perip 4;
limit_conn_status 429;
```
Уберите `buffer=` и `flush=` из `access_log`, чтобы строки попадали в лог сразу.

## Безопасность
- Файлы данных (`logviewer-data/`) защищены от чтения через браузер, ключ API в браузер не передаётся.
- Пока `AUTH_PASS` равен `change-me`, вход в панель не с localhost запрещён.
- Никогда не блокируются: ваши IP (с которых открывали панель), IP сервера, локальные сети, белый список, подтверждённые поисковики.

## Связанные проекты
- **[murkir-ipset-api](https://github.com/Murkirpus/murkir-ipset-api)** — API блокировки IP через ipset/nftables, с которым работает MurKir Shield

## Лицензия
[MIT](LICENSE)
