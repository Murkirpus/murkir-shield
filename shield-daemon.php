<?php
/**
 * MurKir Shield — потоковая автозащита (systemd-демон) для logs.php.
 *
 * Правила, белые списки, журнал, сроки и повторные баны берутся из logs.php без изменений:
 * autobanFeed() / autobanCheck() / autobanWhitelist() / blockApiCall() и хранилище logviewer-data.
 * Разница только в том, КОГДА они работают: демон читает логи непрерывно (каждые 0,25 с)
 * и принимает решения каждые 0,5 с, а не раз в минуту из cron.
 *
 * Устройство:
 *   главный процесс  — читает логи, считает признаки в памяти, решает; никогда не ждёт сеть и DNS;
 *   процесс «ban»    — выполняет блокировки через API (curl может ждать до 20 с — главный цикл не встаёт);
 *   процесс «rdns»   — проверяет поисковиков по обратному DNS и раз в сутки качает диапазоны IP Google/Bing.
 *
 * Пока демон работает, он держит блокировку autoban_lock: проверка из cron и со страницы logs.php
 * автоматически пропускается («уже выполняется»), двойных банов не будет.
 *
 * Запуск:   php shield-daemon.php            — обычный режим (через systemd: murkir-shield.service)
 *           php shield-daemon.php --ranges   — скачать диапазоны IP Googlebot/Bingbot и выйти
 * Сигналы:  SIGTERM/SIGINT — сохранить состояние и выйти; SIGHUP — перечитать настройки и список логов.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

// ───────────── Настройки ─────────────
const SHIELD_LOGS_PHP       = __DIR__ . '/logs.php';   // путь к logs.php (с правками для подключения как библиотеки)
const SHIELD_TICK           = 0.25;      // как часто читать логи, секунд
const SHIELD_CHECK_EVERY    = 0.5;       // как часто применять правила к IP с новыми запросами
const SHIELD_GC_EVERY       = 10;        // уборка памяти
const SHIELD_SAVE_EVERY     = 30;        // сохранение состояния на диск (на случай OOM / SIGKILL)
const SHIELD_CFG_EVERY      = 5;         // перечитать режим и правила, изменённые на странице
const SHIELD_JOURNAL_EVERY  = 30;        // перечитать журнал (результаты банов пишет процесс «ban»)
const SHIELD_DISCOVER_EVERY = 60;        // искать новые / пропавшие логи
const SHIELD_STATS_EVERY    = 60;        // строка статистики в journald
const SHIELD_MAX_IPS        = 20_000;    // предел отслеживаемых IP (защита памяти); лишние — самые давние
const SHIELD_MAX_LAG        = 50_000_000;// если отстали больше чем на 50 МБ — догоняем с последних MAX_CHUNK_BYTES
const SHIELD_READ_MAX       = 8_000_000; // максимум байт за тик с одного файла
const SHIELD_MAX_LINE       = 65_536;    // строки длиннее — мусор, пропускаем
const SHIELD_MEMORY_LIMIT   = '96M' ;    // ниже MemoryMax в systemd, чтобы PHP упал с понятной ошибкой раньше OOM-kill
const SHIELD_RANGES_URLS    = [          // официальные списки IP поисковых роботов
    'Googlebot' => 'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
    'Bingbot'   => 'https://www.bing.com/toolbox/bingbot.json',
];
const SHIELD_RANGES_TTL     = 86400;     // обновлять диапазоны раз в сутки
const SHIELD_BY             = 'демон';   // так решения подписаны в журнале logs.php

ini_set('memory_limit', SHIELD_MEMORY_LIMIT);
foreach (['pcntl_fork', 'pcntl_async_signals', 'stream_socket_pair', 'posix_kill'] as $fn) {
    if (!function_exists($fn)) { fwrite(STDERR, "Нет функции {$fn}(): нужны расширения pcntl и posix для PHP CLI\n"); exit(1); }
}

// Подключаем logs.php как библиотеку. Если в нём нет правки LOGVIEWER_LIB — он нарисовал бы страницу, поэтому буфер.
define('LOGVIEWER_LIB', true);
ob_start();
require SHIELD_LOGS_PHP;
ob_end_clean();
if (!defined('LOGVIEWER_LIB_OK')) {
    fwrite(STDERR, "logs.php без правки для подключения как библиотеки. Возьмите обновлённый logs.php из комплекта.\n");
    exit(1);
}

function slog(string $msg): void { fwrite(STDOUT, $msg . PHP_EOL); }

// ───────────── Чтение лога «как tail -F» ─────────────
final class Follower
{
    /** @var resource|null */
    public $fh = null;
    public int $ino = 0;
    public int $pos = 0;          // сколько байт файла уже прочитано
    public string $buf = '';      // хвост без перевода строки (строка ещё дописывается)
    public int $parsed = 0;
    public int $bad = 0;
    private bool $dropFirst = false;

    public function __construct(public readonly string $key, public readonly string $path) {}

    /** $pos === null — начать с конца файла; другой inode или файл стал короче — с начала */
    public function open(?int $pos, ?int $ino): bool
    {
        clearstatcache(true, $this->path);
        $fh = @fopen($this->path, 'rb');
        if (!$fh) return false;
        $st = fstat($fh);
        $size = (int)($st['size'] ?? 0); $cur = (int)($st['ino'] ?? 0);
        if ($pos === null) $pos = $size;
        elseif ($ino !== $cur || $pos > $size) $pos = 0;
        $this->dropFirst = false;
        if ($size - $pos > SHIELD_MAX_LAG) { $pos = max(0, $size - MAX_CHUNK_BYTES); $this->dropFirst = true; }
        $this->close();
        $this->fh = $fh; $this->ino = $cur; $this->pos = $pos; $this->buf = '';
        return true;
    }

    public function close(): void
    {
        if ($this->fh) @fclose($this->fh);
        $this->fh = null;
    }

    /** Новые полные строки. Ротацию (новый inode) и copytruncate обрабатывает сам. */
    public function poll(): array
    {
        if (!$this->fh) return [];
        $lines = $this->drain();                               // сначала дочитываем то, что уже открыто
        clearstatcache(true, $this->path);
        $ino = @fileinode($this->path);
        if ($ino !== false && $ino !== $this->ino) {           // logrotate переименовал файл — переходим на новый
            if ($this->open(0, (int)$ino)) array_push($lines, ...$this->drain());
        } elseif ((int)(fstat($this->fh)['size'] ?? 0) < $this->pos) {
            $this->pos = 0; $this->buf = '';                   // copytruncate: файл обрезали
        }
        return $lines;
    }

    /** Смещение для сохранения: незаконченную строку перечитаем после рестарта */
    public function savedOffset(): int { return max(0, $this->pos - strlen($this->buf)); }

    private function drain(): array
    {
        fseek($this->fh, $this->pos);                          // сбрасывает признак EOF, чтобы увидеть дописанное
        $data = ''; $left = SHIELD_READ_MAX;
        while ($left > 0) {
            $chunk = fread($this->fh, min(262144, $left));
            if ($chunk === false || $chunk === '') break;
            $data .= $chunk; $left -= strlen($chunk);
        }
        if ($data === '') return [];
        $this->pos += strlen($data);
        $data = $this->buf . $data;
        $nl = strrpos($data, "\n");
        if ($nl === false) { $this->buf = strlen($data) > SHIELD_MAX_LINE ? '' : $data; return []; }
        $this->buf = (string)substr($data, $nl + 1);
        if (strlen($this->buf) > SHIELD_MAX_LINE) $this->buf = '';
        $lines = explode("\n", substr($data, 0, $nl));
        if ($this->dropFirst) { array_shift($lines); $this->dropFirst = false; }
        return $lines;
    }
}

// ───────────── Канал к дочернему процессу (неблокирующая запись) ─────────────
final class Chan
{
    private string $out = '';
    /** @param resource $sock */
    public function __construct(public $sock) {}
    public function send(string $line): void
    {
        if (strlen($this->out) > 1_000_000) return;           // исполнитель завис — не раздуваем память
        $this->out .= $line . "\n";
        $this->flush();
    }
    public function flush(): void
    {
        if ($this->out === '') return;
        $w = @fwrite($this->sock, $this->out);
        if ($w) $this->out = (string)substr($this->out, $w);
    }
    public function drainBlocking(): void
    {
        stream_set_blocking($this->sock, true);
        if ($this->out !== '') @fwrite($this->sock, $this->out);
        $this->out = '';
    }
}

/** Цикл дочернего процесса: по строке на задание; при закрытии канала дорабатывает очередь и выходит */
function workerLoop($sock, callable $job, ?callable $idle = null, int $idleEvery = 3600): void
{
    stream_set_blocking($sock, false);
    $buf = ''; $nextIdle = 0;
    while (true) {
        if ($idle && time() >= $nextIdle) { try { $idle(); } catch (\Throwable $e) { slog('фон: ' . $e->getMessage()); } $nextIdle = time() + $idleEvery; }
        $r = [$sock]; $w = $e = null;
        if (@stream_select($r, $w, $e, 30) === false) continue;
        if (!$r) continue;
        $chunk = fread($sock, 65536);
        $eof = ($chunk === '' || $chunk === false) && feof($sock);
        $buf .= (string)$chunk;
        while (($p = strpos($buf, "\n")) !== false) {
            $line = substr($buf, 0, $p); $buf = (string)substr($buf, $p + 1);
            if ($line === '') continue;
            try { $job($line); } catch (\Throwable $ex) { slog('ошибка задания: ' . $ex->getMessage()); }
        }
        if ($eof) return;
    }
}

/** Процесс «ban»: проверка списка iptables и вызов API блокировки — как $punish в runAutoban() */
function banJob(string $line): void
{
    $j = json_decode($line, true);
    if (!is_array($j) || empty($j['target']) || empty($j['rec'])) return;
    $target = (string)$j['target']; $timeout = (int)$j['timeout']; $rec = (array)$j['rec'];
    $fw = fwList();                                            // кеш 20 с, как в logs.php
    foreach ($fw['list'] ?? [] as $fe) {
        if ($fe['ip'] === $target || (str_contains($fe['ip'], '/') && !str_contains($target, '/') && ipInCidr($target, $fe['ip']))) {
            autobanJournal([$rec + ['act' => 'skip', 'note' => 'уже в iptables: ' . $fe['ip']]]);
            return;
        }
    }
    $r = blockApiCall('block', $target, $timeout);
    if ($r['ok']) {
        blockStore(function ($d) use ($target, $timeout, $rec) {
            $d[$target] = ['ip' => $target, 'at' => time(), 'until' => time() + $timeout, 'timeout' => $timeout, 'reason' => '🤖 ' . $rec['why'], 'by' => 'автозащита'];
            return $d;
        });
        autobanJournal([$rec + ['act' => 'ban', 'note' => mb_substr($r['resp'], 0, 200)]]);
        storeWrite('fwcache', []);
        slog("⛔ {$target} на {$timeout} с — {$rec['why']}");
    } else {
        autobanJournal([$rec + ['act' => 'error', 'note' => mb_substr($r['err'] ?: ('HTTP ' . $r['code'] . ': ' . $r['resp']), 0, 200)]]);
        slog("⚠️ не удалось заблокировать {$target}: HTTP {$r['code']} {$r['err']}");
    }
}

function httpGet(string $url): string
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_CONNECTTIMEOUT => 7,
        CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3, CURLOPT_USERAGENT => API_USER_AGENT]);
    $r = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return is_string($r) && $code === 200 ? $r : '';
}

/** Скачивает диапазоны IP Googlebot/Bingbot в logviewer-data/search_ranges. При сбое сети старые не стирает. */
function updateRanges(bool $force = false): int
{
    $cur = storeRead('search_ranges');
    if (!$force && ($cur['t'] ?? 0) > time() - SHIELD_RANGES_TTL && !empty($cur['cidrs'])) return count($cur['cidrs']);
    $cidrs = [];
    foreach (SHIELD_RANGES_URLS as $bot => $url) {
        $j = json_decode(httpGet($url), true);
        $got = 0;
        foreach ((array)($j['prefixes'] ?? []) as $p) {
            $c = normTarget((string)($p['ipv4Prefix'] ?? $p['ipv6Prefix'] ?? ''));
            if ($c !== '') { $cidrs[$c] = $bot; $got++; }
        }
        if (!$got) {                                           // этот список не скачался — оставляем прежний
            foreach ((array)($cur['cidrs'] ?? []) as $c => $b) if ($b === $bot) $cidrs[$c] = $b;
            slog("диапазоны {$bot}: не удалось скачать, оставлены прежние");
        }
    }
    if ($cidrs) storeWrite('search_ranges', ['t' => time(), 'cidrs' => $cidrs]);
    return count($cidrs);
}

/** Процесс «rdns»: проверка «Googlebot / YandexBot…» по обратному DNS (результат — в кеш rdns logs.php) */
function rdnsJob(string $line): void
{
    [$bot, $ip] = explode('|', $line, 2) + ['', ''];
    if ($bot !== '' && $ip !== '') verifyBot($bot, $ip, true);
}

// ───────────── Главный процесс ─────────────
final class Shield
{
    private bool $running = true;
    private bool $hup = false;
    private bool $started = false;
    /** @var resource|null */
    private $lock = null;

    private array $ips = [];          // признаки по IP — та же структура, что в autoban_state
    private array $dirty = [];        // IP с новыми запросами с прошлой проверки
    private int $staticAt = 0;
    private array $files = [];        // смещения логов (формат autoban_state['files'])
    /** @var Follower[] */
    private array $followers = [];

    private array $cfg = ['mode' => 'off', 'rules' => []];
    private array $whiteUrls = [];
    private string $selfName;
    private array $journal = [];      // журнал за 7 дней в памяти (повторные баны, «атака подсетью», предохранитель)
    private array $add = [];          // новые записи журнала, ещё не сохранённые
    private array $queued = [];       // отправлены процессу «ban» — не дублируем
    private array $ranges = [];       // CIDR => Googlebot / Bingbot
    private array $rdnsSent = [];
    private array $workers = [];
    private array $stat = ['lines' => 0, 'bad' => 0, 'dec' => 0, 'ban' => 0];
    private int $checkMs = 0;
    private array $t = [];

    public function __construct() { $this->selfName = '/' . basename(SHIELD_LOGS_PHP); }

    public function run(): void
    {
        pcntl_async_signals(true);
        pcntl_signal(SIGTERM, function () { $this->running = false; });
        pcntl_signal(SIGINT, function () { $this->running = false; });
        pcntl_signal(SIGHUP, function () { $this->hup = true; });
        @cli_set_process_title('murkir-shield: main');

        $this->takeLock();
        if (!$this->running) return;
        $this->load();
        $this->workers['ban']  = $this->spawn('ban', fn($s) => workerLoop($s, 'banJob'));
        $this->workers['rdns'] = $this->spawn('rdns', fn($s) => workerLoop($s, 'rdnsJob', fn() => updateRanges(), 3600));
        $this->started = true;
        $this->t['stats'] = microtime(true);
        slog(sprintf('запущен: режим «%s», логов %d, IP под наблюдением %d, данные %s',
            $this->cfg['mode'], count($this->followers), count($this->ips), dataDir()));

        while ($this->running) {
            $t0 = microtime(true); $now = time();
            if ($this->hup) { $this->hup = false; $this->reloadCfg(true); $this->discover(); $this->loadRanges(); slog('SIGHUP: настройки и список логов перечитаны'); }
            $this->readLogs($now);
            if ($this->every('check', SHIELD_CHECK_EVERY)) $this->check($now);
            foreach ($this->workers as $w) $w['chan']->flush();
            if ($this->every('cfg', SHIELD_CFG_EVERY)) $this->reloadCfg();
            if ($this->every('journal', SHIELD_JOURNAL_EVERY)) $this->reloadJournal($now);
            if ($this->every('gc', SHIELD_GC_EVERY)) { $this->gc($now); $this->reap(); $this->loadRanges(); }
            if ($this->every('save', SHIELD_SAVE_EVERY)) $this->save($now);
            if ($this->every('discover', SHIELD_DISCOVER_EVERY)) $this->discover();
            if ($this->every('stats', SHIELD_STATS_EVERY)) $this->stats();
            $sleep = SHIELD_TICK - (microtime(true) - $t0);
            if ($sleep > 0 && $this->running) usleep((int)($sleep * 1e6));   // сигнал прерывает сон сразу
        }
        $this->shutdown();
    }

    private function every(string $k, float $sec): bool
    {
        $now = microtime(true);
        if (($this->t[$k] ?? 0) > $now - $sec) return false;
        $this->t[$k] = $now;
        return true;
    }

    /** Та же блокировка, что у runAutoban(): пока она у нас, cron и страница проверку пропускают */
    private function takeLock(): void
    {
        $this->lock = @fopen(dataPath('autoban_lock'), 'c');
        if (!$this->lock) { slog('не могу открыть ' . dataPath('autoban_lock') . ' — проверьте права на ' . dataDir()); exit(1); }
        $said = false;
        while ($this->running && !flock($this->lock, LOCK_EX | LOCK_NB)) {
            if (!$said) { slog('жду, пока закончится проверка из cron / со страницы…'); $said = true; }
            sleep(1);
        }
    }

    private function load(): void
    {
        $st = storeRead('autoban_state', ['files' => [], 'ips' => []]);
        $this->ips = is_array($st['ips'] ?? null) ? $st['ips'] : [];
        $this->files = is_array($st['files'] ?? null) ? $st['files'] : [];
        $this->staticAt = (int)($st['static'] ?? 0);
        $this->reloadCfg(true);
        $this->reloadJournal(time());
        $this->loadRanges();
        $this->discover();
    }

    private function spawn(string $name, callable $body): array
    {
        $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        if (!$pair) { slog("не удалось создать канал для «{$name}»"); exit(1); }
        $pid = pcntl_fork();
        if ($pid === -1) { slog("не удалось запустить процесс «{$name}»"); exit(1); }
        if ($pid === 0) {                                      // дочерний процесс
            fclose($pair[0]);
            pcntl_signal(SIGTERM, SIG_DFL); pcntl_signal(SIGINT, SIG_IGN); pcntl_signal(SIGHUP, SIG_IGN);
            @cli_set_process_title('murkir-shield: ' . $name);
            try { $body($pair[1]); } catch (\Throwable $e) { slog("{$name}: " . $e->getMessage()); }
            exit(0);
        }
        fclose($pair[1]);
        stream_set_blocking($pair[0], false);
        return ['pid' => $pid, 'name' => $name, 'body' => $body, 'chan' => new Chan($pair[0]), 'at' => time()];
    }

    /** Упавший дочерний процесс перезапускаем (не чаще раза в 5 с) */
    private function reap(): void
    {
        foreach ($this->workers as $name => $w) {
            $r = pcntl_waitpid($w['pid'], $status, WNOHANG);
            if ($r === 0 || $w['at'] > time() - 5) continue;
            slog("процесс «{$name}» завершился — перезапускаю");
            @fclose($w['chan']->sock);
            $this->workers[$name] = $this->spawn($name, $w['body']);
        }
    }

    private function reloadCfg(bool $quiet = false): void
    {
        $old = $this->cfg['mode'];
        $this->cfg = autobanSettings();
        $this->whiteUrls = autobanWhite()['url'];
        if (!$quiet && $old !== $this->cfg['mode']) slog("режим: «{$old}» → «{$this->cfg['mode']}»");
    }

    private function reloadJournal(int $now): void
    {
        $pending = array_filter($this->journal, fn($j) => !empty($j['pending']) && $j['t'] > $now - 60);
        $this->journal = array_values(array_filter(autobanJournal(), fn($j) => ($j['t'] ?? 0) > $now - 7 * 86400));
        foreach ($pending as $p) $this->journal[] = $p;        // бан ещё выполняется — учитываем до записи в файл
    }

    private function loadRanges(): void { $this->ranges = (array)(storeRead('search_ranges')['cidrs'] ?? []); }

    private function rangeOf(string $ip): string
    {
        foreach ($this->ranges as $cidr => $bot) if (ipInCidr($ip, (string)$cidr)) return (string)$bot;
        return '';
    }

    private function discover(): void
    {
        foreach (discoverLogs() as $key => $l) {
            $key = (string)$key;
            if (isset($this->followers[$key]) || !$l['readable'] || !empty($this->files[$key]['x'])) continue;
            $f = new Follower($key, $l['path']);
            $saved = $this->files[$key] ?? null;
            // при старте без сохранённого смещения — с конца (как cron); новый лог, появившийся позже, — с начала
            $pos = $saved ? (int)$saved['o'] : ($this->started ? 0 : null);
            if (!$f->open($pos, $saved ? (int)$saved['i'] : null)) continue;
            $this->followers[$key] = $f;
            if ($this->started) slog('новый лог: ' . $l['path']);
        }
        foreach ($this->followers as $key => $f) {
            if (@is_file($f->path)) continue;
            $f->close(); unset($this->followers[$key]);
            slog('лог пропал: ' . $f->path);
        }
    }

    private function readLogs(int $now): void
    {
        $feed = $this->cfg['mode'] !== 'off';
        foreach ($this->followers as $key => $f) {
            try { $lines = $f->poll(); }
            catch (\Throwable $e) { slog("ошибка чтения {$f->path}: " . $e->getMessage()); $f->close(); unset($this->followers[$key]); continue; }
            foreach ($lines as $line) {
                if ($line === '' || strlen($line) > SHIELD_MAX_LINE || trim($line) === '') continue;
                try { $e = parseLine($line); } catch (\Throwable) { $e = null; }
                if ($e === null) { $f->bad++; $this->stat['bad']++; continue; }
                $f->parsed++;
                if ($feed) $this->feed($e, $now);
            }
            if ($f->parsed === 0 && $f->bad > 20) {            // ни одной строки посещений — это не access-лог
                $this->files[$key] = ['o' => $f->savedOffset(), 'i' => $f->ino, 'x' => 1];
                $f->close(); unset($this->followers[$key]);
                slog('пропускаю, не похоже на access-лог: ' . $f->path);
            }
        }
    }

    /** Одна строка лога → признаки IP (как цикл по строкам в runAutoban) */
    private function feed(array $e, int $now): void
    {
        if ($e['t'] < $now - AUTOBAN_WINDOW) return;
        $ip = normIp($e['ip']);
        if ($ip === '' || autobanUrlWhite($e['p'], $this->whiteUrls)) return;
        $x = $this->ips[$ip] ?? ['m' => []];
        $res = autobanFeed($x, $e, str_ends_with(explode('?', $e['p'], 2)[0], $this->selfName));
        if (!$res) return;
        if ($res === 2) $this->staticAt = $now;
        $this->ips[$ip] = $x;
        $this->dirty[$ip] = true;
        $this->stat['lines']++;
        foreach (array_keys($x['sb'] ?? []) as $bot) {         // представился поисковиком — проверим rDNS в фоне
            $k = $bot . '|' . $ip;
            if (($this->rdnsSent[$k] ?? 0) > $now - 3600) continue;
            $this->rdnsSent[$k] = $now;
            $this->workers['rdns']['chan']->send($k);
        }
    }

    /** Правила к IP с новыми запросами (как блок «решения» в runAutoban, но без сетевых вызовов) */
    private function check(int $now): void
    {
        if ($this->cfg['mode'] === 'off' || !$this->dirty) { $this->dirty = []; return; }
        $t0 = microtime(true);
        $rules = $this->cfg['rules'];
        $staticLogged = $this->staticAt > $now - 86400;
        $fresh = [];
        foreach ($this->dirty as $ip => $_) {
            $ip = (string)$ip;
            $x = $this->ips[$ip] ?? null;
            if ($x === null || ($x['done'] ?? 0) > $now - AUTOBAN_WINDOW) continue;
            $lookups = 15;                                     // ≥15 — verifyBot() берёт только кеш, DNS делает процесс «rdns»
            try { $hit = autobanCheck($ip, $x, $rules, $lookups, $staticLogged); }
            catch (\Throwable $ex) { slog("правила для {$ip}: " . $ex->getMessage()); continue; }
            if (!$hit) continue;
            [$rule, $why, $timeout, $score] = $hit;
            $this->ips[$ip]['done'] = $now;
            $this->stat['dec']++;
            $rec = ['t' => $now, 'ip' => $ip, 'rule' => $rule, 'why' => $why, 'n' => $x['n'] ?? '', 'k' => $x['k'] ?? '', 'by' => SHIELD_BY, 'sc' => $score];
            if (($bot = $this->rangeOf($ip)) !== '') { $this->note($rec + ['act' => 'skip', 'note' => "официальный IP {$bot}"]); continue; }
            if (($wl = autobanWhitelist($ip, $x, $rule, $lookups)) !== '') { $this->note($rec + ['act' => 'skip', 'note' => $wl]); continue; }
            if ($this->punish($ip, $rec, (int)$timeout, $now)) $fresh[subnetOfIp($ip)] = true;
        }
        $this->dirty = [];
        unset($fresh['']);
        if ($fresh) $this->subnets($fresh, $now);
        if ($this->add) { autobanJournal($this->add); $this->add = []; }
        $this->checkMs = (int)((microtime(true) - $t0) * 1000);
    }

    private function note(array $rec): void { $this->add[] = $rec; $this->journal[] = $rec; }

    /** Как $punish в runAutoban. Возвращает true для ban / watch / limit (их считает правило «атака подсетью») */
    private function punish(string $target, array $rec, int $timeout, int $now): bool
    {
        $active = blockStore();
        if (isset($active[$target]) && ($active[$target]['until'] ?? 0) > $now) { $this->note($rec + ['act' => 'skip', 'note' => 'уже заблокирован']); return false; }
        if (($this->queued[$target] ?? 0) > $now - 120) return false;
        if (AUTOBAN_REPEAT_X2) {
            $prev = count(array_filter($this->journal, fn($j) => $j['ip'] === $target && $j['act'] === 'ban' && $j['t'] > $now - 7 * 86400));
            if ($prev) { $timeout = min(2592000, $timeout * (2 ** $prev)); $rec['why'] .= " · повторно ({$prev}), срок ×" . (2 ** $prev); }
        }
        $rec['timeout'] = $timeout;
        if ($this->cfg['mode'] === 'watch') { $this->note($rec + ['act' => 'watch']); return true; }
        if (!blockEnabled()) { $this->note($rec + ['act' => 'error', 'note' => 'не настроен BLOCK_API_KEY']); return false; }
        $bansHour = count(array_filter($this->journal, fn($j) => $j['act'] === 'ban' && $j['t'] > $now - 3600));
        if ($bansHour >= AUTOBAN_MAX_PER_HOUR) { $this->note($rec + ['act' => 'limit', 'note' => 'предохранитель: ' . AUTOBAN_MAX_PER_HOUR . ' банов в час']); return true; }
        $this->workers['ban']['chan']->send(json_encode(['target' => $target, 'timeout' => $timeout, 'rec' => $rec],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
        $this->queued[$target] = $now;
        $this->journal[] = $rec + ['act' => 'ban', 'pending' => 1];   // только в памяти: в файл итог запишет процесс «ban»
        $this->stat['ban']++;
        return true;
    }

    /** «Атака подсетью» — та же логика, что в runAutoban */
    private function subnets(array $fresh, int $now): void
    {
        $r = $this->cfg['rules']['subnet'] ?? ['on' => false];
        if (empty($r['on'])) return;
        $nets = []; $seen = [];
        foreach ($this->journal as $j) {
            if ($j['t'] <= $now - 3600) continue;
            if (str_contains($j['ip'], '/')) { $seen[$j['ip']] = true; continue; }
            if (!in_array($j['act'], ['ban', 'watch', 'limit'], true)) continue;
            $net = subnetOfIp($j['ip']);
            if ($net !== '') $nets[$net][$j['ip']] = true;
        }
        foreach (array_keys($fresh) as $net) {
            $net = (string)$net; $ips = $nets[$net] ?? [];
            if (count($ips) < $r['ips'] || isset($seen[$net]) || isset($this->queued[$net])) continue;
            $rec = ['t' => $now, 'ip' => $net, 'rule' => 'subnet', 'why' => 'атака подсетью: ' . count($ips) . ' нарушителей за час (' . implode(', ', array_slice(array_keys($ips), 0, 4)) . (count($ips) > 4 ? '…' : '') . ')', 'n' => '', 'k' => '', 'by' => SHIELD_BY];
            $wl = protectCidr($net, '');
            if ($wl === '') foreach (array_keys(storeRead('admins')) as $a) if (ipInCidr((string)$a, $net)) { $wl = 'в подсети ваш IP ' . $a; break; }
            if ($wl === '') foreach (autobanWhite()['ip'] as $a) if (ipInCidr(explode('/', $a)[0], $net) || (str_contains($a, '/') && ipInCidr(explode('/', $net)[0], $a))) { $wl = 'в подсети адрес из белого списка ' . $a; break; }
            if ($wl === '') foreach (storeRead('rdns') as $ck => $v) {
                if (($v['res'] ?? '') === 'ok' && ipInCidr(substr((string)$ck, (int)strpos((string)$ck, '|') + 1), $net)) { $wl = 'в подсети подтверждённый поисковик'; break; }
            }
            if ($wl === '') foreach ($this->ranges as $c => $bot) {
                if (ipInCidr(explode('/', (string)$c)[0], $net) || ipInCidr(explode('/', $net)[0], (string)$c)) { $wl = "в подсети официальные IP {$bot}"; break; }
            }
            if ($wl !== '') { $this->note($rec + ['act' => 'skip', 'note' => $wl]); continue; }
            $this->punish($net, $rec, (int)$r['timeout'], $now);
        }
    }

    /** Уборка: старые минуты, неактивные IP, предел числа IP, служебные списки */
    private function gc(int $now): void
    {
        $minKeep = intdiv($now - AUTOBAN_WINDOW, 60);
        foreach ($this->ips as $ip => &$x) {
            foreach ($x['m'] as $m => $_) if ((int)$m < $minKeep) unset($x['m'][$m]);
            if (!$x['m'] && (($x['done'] ?? 0) < $now - AUTOBAN_WINDOW)) unset($this->ips[$ip]);
        }
        unset($x);
        if (count($this->ips) > SHIELD_MAX_IPS) {
            uasort($this->ips, fn($a, $b) => ($b['last'] ?? 0) <=> ($a['last'] ?? 0));
            $this->ips = array_slice($this->ips, 0, (int)(SHIELD_MAX_IPS * 0.9), true);
            slog('предел IP: оставлены ' . count($this->ips) . ' самых свежих');
        }
        $this->rdnsSent = array_filter($this->rdnsSent, fn($t) => $t > $now - 3600);
        $this->queued = array_filter($this->queued, fn($t) => $t > $now - 120);
        gc_collect_cycles();
    }

    /** Состояние в том же формате, что пишет runAutoban — страница logs.php и cron (если демон остановлен) его понимают */
    private function save(int $now): void
    {
        foreach ($this->followers as $key => $f) $this->files[$key] = ['o' => $f->savedOffset(), 'i' => $f->ino];
        storeWrite('autoban_state', ['files' => $this->files, 'ips' => $this->ips, 'static' => $this->staticAt, 'last' => $now, 'trigger' => SHIELD_BY]);
        storeWrite('autoban_last', ['ok' => true, 't' => $now, 'by' => SHIELD_BY, 'mode' => $this->cfg['mode'], 'lines' => $this->stat['lines'],
            'ips' => count($this->ips), 'decisions' => $this->stat['dec'], 'ms' => $this->checkMs, 'cron' => $now]);
    }

    private function stats(): void
    {
        slog(sprintf('за минуту: строк %d, битых %d, решений %d, банов %d · IP %d · логов %d · память %.1f МБ',
            $this->stat['lines'], $this->stat['bad'], $this->stat['dec'], $this->stat['ban'], count($this->ips),
            count($this->followers), memory_get_usage(true) / 1048576));
        $this->stat = ['lines' => 0, 'bad' => 0, 'dec' => 0, 'ban' => 0];
    }

    private function shutdown(): void
    {
        slog('останавливаюсь: сохраняю состояние…');
        if ($this->add) { autobanJournal($this->add); $this->add = []; }
        $this->save(time());
        foreach ($this->workers as $w) { $w['chan']->drainBlocking(); @fclose($w['chan']->sock); }   // дети доработают очередь и выйдут
        $until = microtime(true) + 8;
        foreach ($this->workers as $w) {
            while (pcntl_waitpid($w['pid'], $status, WNOHANG) === 0 && microtime(true) < $until) usleep(100_000);
            if (pcntl_waitpid($w['pid'], $status, WNOHANG) === 0) posix_kill($w['pid'], SIGTERM);
        }
        foreach ($this->followers as $f) $f->close();
        if ($this->lock) { flock($this->lock, LOCK_UN); fclose($this->lock); }
        slog('остановлен');
    }
}

// ───────────── Точка входа ─────────────
if (in_array('--ranges', $argv ?? [], true)) {
    $n = updateRanges(true);
    slog("диапазонов IP поисковиков: {$n} → " . dataPath('search_ranges'));
    exit($n ? 0 : 1);
}
(new Shield())->run();
