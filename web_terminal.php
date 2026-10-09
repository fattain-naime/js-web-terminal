<?php
/*
 * Web Terminal Pro - browser + CLI terminal for hosts with no shell access.
 *
 * @ Author Fattain Naime
 * @ Website: https://iamnaime.info.bd
 * @ Github: https://github.com/fattain-naime/js-web-terminal
 * @ License: GPL-2.0
 *
 * Enable terminal access where terminal access is forbidden - from a browser
 * AND from a real terminal via the bundled CLI client (webterm_client.py).
 *
 * ======================= SETUP =======================
 * 1) Password (for the browser UI). Generate a bcrypt hash:
 *      php -r "echo password_hash('your-password', PASSWORD_DEFAULT), PHP_EOL;"
 *    Paste it into TERMINAL_PASSWORD_HASH below. Login stays disabled until
 *    a hash is set.
 *
 * 2) API key (for the CLI client / scripts, optional but recommended).
 *    Generate a random key and its bcrypt hash:
 *      php -r "$k=bin2hex(random_bytes(24)); echo $k, PHP_EOL, password_hash($k, PASSWORD_DEFAULT), PHP_EOL;"
 *    Keep the first line (the raw key) for yourself (pass it to the CLI via
 *    --api-key or the WEBTERM_API_KEY env var). Paste the second line (the
 *    hash) into TERMINAL_API_KEY_HASH below. The raw key is never stored.
 *
 * See README.md for the full feature list, security notes and CLI usage.
 */

error_reporting(E_ALL);
// Never leak paths or warnings to the browser. Errors go to the server log.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// ======================= CONFIGURATION =======================

// bcrypt hash of your browser login password. Empty = browser login disabled.
// A legacy 32-char MD5 hash still works, but bcrypt is strongly recommended.
const TERMINAL_PASSWORD_HASH = '';

// bcrypt hash of your CLI/API key. Empty = API key auth disabled (CLI can
// still use --password to log in like the browser does).
const TERMINAL_API_KEY_HASH = '';

// Optional IP allow-list, e.g. ['203.0.113.10', '2001:db8::1']. Empty = allow all.
const TERMINAL_ALLOWED_IPS = [];

const TERMINAL_MAX_ATTEMPTS    = 5;        // failed logins/API key checks before lockout (per IP)
const TERMINAL_LOCKOUT_SECONDS = 300;      // lockout duration
const TERMINAL_IDLE_TIMEOUT    = 1800;     // browser session auto-logout after inactivity (seconds)

// How long a command may run before `exec` returns an in-progress job instead
// of the final result. Short commands feel instant; long ones become a
// background job you poll - so they are never cut off by a PHP time limit.
const TERMINAL_SYNC_GRACE_MS   = 1200;
const TERMINAL_JOB_MAX_RUNTIME = 3600;     // background jobs are auto-killed after this many seconds
const TERMINAL_JOB_RETENTION   = 1800;     // finished job output is kept this long, then garbage-collected
const TERMINAL_COMMAND_TIMEOUT = 60;       // hard timeout on hosts without background-job support (Windows)

const TERMINAL_MAX_OUTPUT      = 1048576;  // max output bytes returned per exec/poll chunk
const TERMINAL_MAX_COMMAND_LEN = 16384;
const TERMINAL_MAX_UPLOAD_BYTES = 26214400; // 25 MB soft cap (also bounded by php.ini post_max_size)

// Where job logs, per-identity working directory and history are kept.
// Defaults next to this script; move it outside the web root if you can,
// and see README.md for webserver rules that keep it from being served.
const TERMINAL_DATA_DIR = __DIR__ . '/.webterm_data';

const TERMINAL_ENABLE_AUDIT_LOG = true;    // append-only log of commands run (not their output)
const TERMINAL_ENABLE_HISTORY   = true;    // remember command history per identity, shared between web + CLI

// ======================= SMALL HELPERS =======================

function wt_is_windows()
{
    return DIRECTORY_SEPARATOR === '\\';
}

function wt_is_https()
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
}

function wt_client_ip()
{
    return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

function wt_headers_common()
{
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header("Content-Security-Policy: frame-ancestors 'none'");
    header('Referrer-Policy: no-referrer');
}

function wt_utf8($s)
{
    if (function_exists('iconv')) {
        $r = @iconv('UTF-8', 'UTF-8//IGNORE', $s);
        if ($r !== false) {
            return $r;
        }
    }
    return preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '?', $s);
}

function wt_json(array $data, $code = 200)
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    $flags = defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0;
    $json  = json_encode($data, $flags);
    if ($json === false) {
        // Command output can contain binary / non-UTF-8 bytes. Never return an empty body.
        array_walk_recursive($data, function (&$v) {
            if (is_string($v)) {
                $v = wt_utf8($v);
            }
        });
        $json = json_encode($data);
    }
    echo $json;
    exit;
}

function wt_bad_request($msg, $code = 400)
{
    wt_json(['ok' => false, 'error' => $msg, 'output' => $msg . "\n"], $code);
}

// ======================= DATA DIRECTORY =======================

function wt_data_dir()
{
    static $dir = null;
    if ($dir !== null) {
        return $dir;
    }
    $dir = rtrim(TERMINAL_DATA_DIR, '/\\');
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    if (!is_dir($dir . '/jobs')) {
        @mkdir($dir . '/jobs', 0700, true);
    }
    // Best-effort: stop common webservers from serving this directory.
    $htaccess = $dir . '/.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess, "Require all denied\nDeny from all\nOrder deny,allow\nDeny from all\n");
    }
    $webconfig = $dir . '/web.config';
    if (!file_exists($webconfig)) {
        @file_put_contents($webconfig, "<configuration>\n  <system.webServer>\n    <security>\n      <authorization>\n        <remove users=\"*\" roles=\"\" verbs=\"\" />\n      </authorization>\n    </security>\n  </system.webServer>\n</configuration>\n");
    }
    return $dir;
}

function wt_jobs_dir()
{
    return wt_data_dir() . '/jobs';
}

function wt_data_writable()
{
    return is_writable(wt_data_dir());
}

// ======================= AUTH: PASSWORD / API KEY =======================

function wt_hash_configured($hash)
{
    return $hash !== '' && strtolower($hash) !== '202cb962ac59075b964b07152d234b70';
}

function wt_password_configured()
{
    return wt_hash_configured(TERMINAL_PASSWORD_HASH);
}

function wt_api_key_configured()
{
    return wt_hash_configured(TERMINAL_API_KEY_HASH);
}

function wt_verify_against_hash($secret, $hash)
{
    if (!wt_hash_configured($hash) || $secret === '') {
        return false;
    }
    if (preg_match('/^[a-f0-9]{32}$/i', $hash)) {
        return hash_equals(strtolower($hash), md5($secret)); // legacy MD5, constant-time compare
    }
    return password_verify($secret, $hash);
}

// ---- Brute-force protection (per IP, stored in the data dir) ----

function wt_lock_file($ip)
{
    return wt_data_dir() . '/lock_' . hash('sha256', $ip) . '.json';
}

function wt_lock_state($ip)
{
    $d = json_decode((string) @file_get_contents(wt_lock_file($ip)), true);
    if (!is_array($d)) {
        $d = [];
    }
    return $d + ['count' => 0, 'until' => 0, 'last' => 0];
}

function wt_locked_for($ip)
{
    $d = wt_lock_state($ip);
    return max(0, (int) $d['until'] - time());
}

function wt_register_failure($ip)
{
    $d = wt_lock_state($ip);
    if (time() - (int) $d['last'] > TERMINAL_LOCKOUT_SECONDS) {
        $d['count'] = 0;
    }
    $d['count']++;
    $d['last'] = time();
    if ($d['count'] >= TERMINAL_MAX_ATTEMPTS) {
        $d['until'] = time() + TERMINAL_LOCKOUT_SECONDS;
        $d['count'] = 0;
    }
    @file_put_contents(wt_lock_file($ip), json_encode($d), LOCK_EX);
}

function wt_clear_failures($ip)
{
    @unlink(wt_lock_file($ip));
}

// ---- Session (browser) ----

function wt_session_valid()
{
    return !empty($_SESSION['auth'])
        && (time() - (int) ($_SESSION['last'] ?? 0)) <= TERMINAL_IDLE_TIMEOUT;
}

function wt_session_destroy()
{
    $_SESSION = [];
    if (session_id() !== '') {
        @session_destroy();
    }
}

/**
 * Resolve who is calling: an API key (stateless, for the CLI) or a browser
 * session (cookie + CSRF). Returns an identity array or null if unauthenticated.
 */
function wt_authenticate($input)
{
    $apiKey = '';
    if (isset($_SERVER['HTTP_X_API_KEY'])) {
        $apiKey = (string) $_SERVER['HTTP_X_API_KEY'];
    } elseif (isset($input['api_key']) && is_string($input['api_key'])) {
        $apiKey = $input['api_key'];
    }

    if ($apiKey !== '') {
        if (!wt_api_key_configured()) {
            return null;
        }
        if (!wt_verify_against_hash($apiKey, TERMINAL_API_KEY_HASH)) {
            return null;
        }
        return ['kind' => 'apikey', 'id' => 'apikey', 'needCsrf' => false];
    }

    if (wt_session_valid()) {
        $token = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? (string) $_SERVER['HTTP_X_CSRF_TOKEN'] : (isset($input['csrf']) ? (string) $input['csrf'] : '');
        if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token)) {
            return null;
        }
        $_SESSION['last'] = time();
        return ['kind' => 'session', 'id' => 'sess_' . substr(hash('sha256', session_id()), 0, 20), 'needCsrf' => true];
    }

    return null;
}

// ======================= PER-IDENTITY STATE (cwd / history) =======================

function wt_cwd_file($identityId)
{
    return wt_data_dir() . '/cwd_' . preg_replace('/[^a-z0-9_]/i', '', $identityId) . '.txt';
}

function wt_get_cwd($identityId)
{
    $f = wt_cwd_file($identityId);
    if (is_file($f)) {
        $v = trim((string) @file_get_contents($f));
        if ($v !== '' && is_dir($v)) {
            return $v;
        }
    }
    return __DIR__;
}

function wt_set_cwd($identityId, $cwd)
{
    @file_put_contents(wt_cwd_file($identityId), $cwd, LOCK_EX);
}

function wt_history_file($identityId)
{
    return wt_data_dir() . '/history_' . preg_replace('/[^a-z0-9_]/i', '', $identityId) . '.log';
}

function wt_history_add($identityId, $command)
{
    if (!TERMINAL_ENABLE_HISTORY) {
        return;
    }
    $line = str_replace(["\r", "\n"], ' ', $command);
    $f    = wt_history_file($identityId);
    @file_put_contents($f, $line . "\n", FILE_APPEND | LOCK_EX);
    // Occasionally trim to the last 500 lines so the file cannot grow forever.
    if (mt_rand(1, 40) === 1 && is_file($f) && filesize($f) > 200000) {
        $lines = file($f, FILE_IGNORE_NEW_LINES);
        if ($lines !== false && count($lines) > 500) {
            file_put_contents($f, implode("\n", array_slice($lines, -500)) . "\n", LOCK_EX);
        }
    }
}

function wt_history_get($identityId, $limit = 200)
{
    $f = wt_history_file($identityId);
    if (!is_file($f)) {
        return [];
    }
    $lines = file($f, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return [];
    }
    return array_slice($lines, -$limit);
}

// ---- Audit log ----

function wt_audit($identityId, $event, $extra = '')
{
    if (!TERMINAL_ENABLE_AUDIT_LOG) {
        return;
    }
    $line = sprintf(
        "%s\t%s\t%s\t%s\t%s\n",
        date('c'),
        wt_client_ip(),
        $identityId,
        $event,
        str_replace(["\r", "\n", "\t"], ' ', (string) $extra)
    );
    @file_put_contents(wt_data_dir() . '/audit.log', $line, FILE_APPEND | LOCK_EX);
}

// ======================= COMMAND EXECUTION ENGINE =======================

function wt_fn_enabled($name)
{
    if (!function_exists($name)) {
        return false;
    }
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    return !in_array($name, $disabled, true);
}

function wt_executors()
{
    return ['proc_open', 'exec', 'shell_exec', 'passthru', 'system', 'popen'];
}

function wt_pick_executor()
{
    foreach (wt_executors() as $fn) {
        if (wt_fn_enabled($fn)) {
            return $fn;
        }
    }
    return null;
}

/** Run via proc_open with a timeout. Returns string output, or null if it could not start. */
function wt_run_proc($script, $timeoutSeconds, $maxBytes)
{
    $windows = wt_is_windows();
    $spec = [
        0 => $windows ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $cmd  = $windows ? $script : 'sh -c ' . escapeshellarg($script);
    $proc = @proc_open($cmd, $spec, $pipes);
    if (!is_resource($proc)) {
        return null;
    }
    if ($windows && isset($pipes[0])) {
        fclose($pipes[0]);
    }
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $out   = '';
    $start = time();
    while (true) {
        $read = [$pipes[1], $pipes[2]];
        $w = null;
        $e = null;
        $n = @stream_select($read, $w, $e, 1);
        if ($n === false) {
            usleep(100000);
        } else {
            foreach ($read as $s) {
                $chunk = fread($s, 8192);
                if ($chunk !== false && $chunk !== '') {
                    $out .= $chunk;
                }
            }
        }
        if (strlen($out) > $maxBytes) {
            @proc_terminate($proc, 9);
            $out = substr($out, 0, $maxBytes) . "\n[output truncated]\n";
            break;
        }
        $st = proc_get_status($proc);
        if (!$st['running']) {
            foreach ([1, 2] as $i) {
                while (($c = fread($pipes[$i], 8192)) !== false && $c !== '') {
                    $out .= $c;
                }
            }
            break;
        }
        if (time() - $start >= $timeoutSeconds) {
            @proc_terminate($proc, 9);
            $out .= "\n[timed out after {$timeoutSeconds}s]\n";
            break;
        }
        if (feof($pipes[1]) && feof($pipes[2])) {
            break;
        }
    }
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    return $out;
}

/** Run $script to completion with the first usable function. Returns string output or null. */
function wt_run($script, $timeoutSeconds = 30, $maxBytes = null)
{
    if ($maxBytes === null) {
        $maxBytes = TERMINAL_MAX_OUTPUT;
    }
    foreach (wt_executors() as $fn) {
        if (!wt_fn_enabled($fn)) {
            continue;
        }
        $out = null;
        switch ($fn) {
            case 'proc_open':
                $out = wt_run_proc($script, $timeoutSeconds, $maxBytes);
                break;
            case 'exec':
                $lines = [];
                $rc = 0;
                if (@exec($script, $lines, $rc) !== false) {
                    $out = implode("\n", $lines);
                }
                break;
            case 'shell_exec':
                $r = @shell_exec($script);
                $out = ($r === false || $r === null) ? null : (string) $r;
                break;
            case 'passthru':
                ob_start();
                @passthru($script);
                $out = ob_get_clean();
                break;
            case 'system':
                ob_start();
                @system($script);
                $out = ob_get_clean();
                break;
            case 'popen':
                $h = @popen($script, 'r');
                if ($h) {
                    $out = '';
                    while (!feof($h)) {
                        $c = fread($h, 8192);
                        if ($c === false) {
                            break;
                        }
                        $out .= $c;
                        if (strlen($out) > $maxBytes) {
                            $out = substr($out, 0, $maxBytes) . "\n[output truncated]\n";
                            break;
                        }
                    }
                    pclose($h);
                }
                break;
        }
        if (is_string($out)) {
            return $out;
        }
    }
    return null;
}

// ---- Background job engine (POSIX hosts only) ----

function wt_job_paths($id)
{
    $base = wt_jobs_dir() . '/' . $id;
    return [
        'log'  => $base . '.log',
        'exit' => $base . '.exit',
        'cwd'  => $base . '.cwd',
        'pid'  => $base . '.pid',
        'meta' => $base . '.meta',
    ];
}

function wt_job_meta_read($id)
{
    $p = wt_job_paths($id);
    if (!is_file($p['meta'])) {
        return null;
    }
    $d = json_decode((string) @file_get_contents($p['meta']), true);
    return is_array($d) ? $d : null;
}

/**
 * Whether the `setsid` utility is available. When it is, a job is started as
 * its own session/process-group leader, so kill() can terminate the whole
 * process tree (the command plus anything it forks) atomically via a
 * process-group signal instead of racing to find children before they get
 * reparented to init. Cached to a flag file so we only probe for it once.
 */
function wt_has_setsid()
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $flag = wt_data_dir() . '/.has_setsid';
    if (is_file($flag)) {
        $cached = (trim((string) @file_get_contents($flag)) === '1');
        return $cached;
    }
    $out = wt_run('command -v setsid >/dev/null 2>&1 && echo yes || echo no', 5, 64);
    $cached = (trim((string) $out) === 'yes');
    @file_put_contents($flag, $cached ? '1' : '0', LOCK_EX);
    return $cached;
}

/**
 * Start $command in the background. Returns the job id, or null if it could
 * not be started (e.g. no executor available).
 */
function wt_job_start($command, $cwd, $identityId)
{
    $id = bin2hex(random_bytes(10));
    $p  = wt_job_paths($id);
    touch($p['log']);

    // An EXIT trap - not a trailing "; echo $?; pwd" - records the result,
    // because the user's command may itself call `exit` (e.g. `exit 7`, or a
    // script it runs does): that would otherwise skip a plain trailer and
    // the job would never record an exit code, so poll() would call it
    // "running" forever. The trap always fires, with $? already set to
    // whatever code the command (or its own `exit`) produced, and it does
    // not touch directories, so a `cd` the command makes still persists.
    $trapAction = '__wt_rc=$?; echo $__wt_rc > ' . escapeshellarg($p['exit']) . '; pwd > ' . escapeshellarg($p['cwd']);
    $innerCmd   = 'trap ' . escapeshellarg($trapAction) . ' EXIT; ' . $command;
    $grouped    = wt_has_setsid();
    $runner   = $grouped ? 'setsid sh -c' : 'nohup sh -c';
    $script   = 'cd ' . escapeshellarg($cwd) . ' 2>/dev/null; ' . $runner . ' ' . escapeshellarg($innerCmd)
        . ' > ' . escapeshellarg($p['log']) . ' 2>&1 < /dev/null & echo $!';

    $pidOut = wt_run($script, 10, 4096);
    if ($pidOut === null) {
        return null;
    }
    $pid = (int) trim($pidOut);

    file_put_contents($p['pid'], (string) $pid, LOCK_EX);
    file_put_contents($p['meta'], json_encode([
        'identity' => $identityId,
        'command'  => $command,
        'cwd'      => $cwd,
        'started'  => time(),
        'pid'      => $pid,
        'grouped'  => $grouped,
    ]), LOCK_EX);

    return $id;
}

function wt_job_running($id)
{
    $p = wt_job_paths($id);
    return !is_file($p['exit']);
}

/** Read new output since $offset. Returns [chunk, newOffset]. */
function wt_job_tail($id, $offset, $maxBytes)
{
    $p = wt_job_paths($id);
    if (!is_file($p['log'])) {
        return ['', $offset];
    }
    $size = filesize($p['log']);
    if ($offset >= $size) {
        return ['', $offset];
    }
    $h = fopen($p['log'], 'rb');
    if (!$h) {
        return ['', $offset];
    }
    fseek($h, $offset);
    $chunk = fread($h, min($maxBytes, $size - $offset));
    $newOffset = $offset + strlen($chunk);
    fclose($h);
    if ($size - $newOffset > 0 && strlen($chunk) >= $maxBytes) {
        $chunk .= "\n[...output continues, keep polling...]\n";
    }
    return [$chunk, $newOffset];
}

function wt_job_result($id)
{
    $p = wt_job_paths($id);
    $exitCode = null;
    $cwd      = null;
    if (is_file($p['exit'])) {
        $exitCode = (int) trim((string) @file_get_contents($p['exit']));
    }
    if (is_file($p['cwd'])) {
        $c = trim((string) @file_get_contents($p['cwd']));
        if ($c !== '') {
            $cwd = $c;
        }
    }
    return [$exitCode, $cwd];
}

function wt_job_signal($pid, $grouped, $signal)
{
    if ($grouped) {
        // The job runs as its own session/process-group leader (started via
        // setsid), so a group signal (negative pid) reaches the command and
        // everything it has forked, in one atomic step.
        if (function_exists('posix_kill')) {
            @posix_kill(-$pid, $signal);
        }
        $sig = $signal === 9 ? 'KILL' : 'TERM';
        wt_run('kill -' . $sig . ' -- -' . escapeshellarg((string) $pid) . ' 2>/dev/null; true', 5, 1024);
    } else {
        // Best effort: signal the process and its direct children (covers a
        // single foreground program). A process that re-forks after this
        // point, or daemonizes itself, may still survive - see README.
        if (function_exists('posix_kill')) {
            @posix_kill($pid, $signal);
        }
        $sig = $signal === 9 ? 'KILL' : 'TERM';
        wt_run('pkill -' . $sig . ' -P ' . escapeshellarg((string) $pid) . ' 2>/dev/null; '
            . 'kill -' . $sig . ' ' . escapeshellarg((string) $pid) . ' 2>/dev/null; true', 5, 1024);
    }
}

function wt_job_kill($id)
{
    $meta = wt_job_meta_read($id);
    if ($meta === null) {
        return false;
    }
    $pid = (int) $meta['pid'];
    if ($pid <= 0) {
        return false;
    }
    $grouped = !empty($meta['grouped']);
    wt_job_signal($pid, $grouped, 15);
    usleep(400000);
    if (wt_job_running($id)) {
        wt_job_signal($pid, $grouped, 9);
        usleep(200000);
    }
    // A killed process never reaches the "echo $? > exitFile" tail of its own
    // wrapper script, so poll() would otherwise show it as running forever.
    // Record the kill ourselves once the process is actually gone.
    if (wt_job_running($id)) {
        $p = wt_job_paths($id);
        @file_put_contents($p['log'], "\n[killed by user]\n", FILE_APPEND);
        @file_put_contents($p['exit'], '143', LOCK_EX);
        @file_put_contents($p['cwd'], $meta['cwd'], LOCK_EX);
    }
    return true;
}

function wt_job_list($identityId, $limit = 50)
{
    $out = [];
    foreach (glob(wt_jobs_dir() . '/*.meta') ?: [] as $metaFile) {
        $id   = basename($metaFile, '.meta');
        $meta = wt_job_meta_read($id);
        if ($meta === null || $meta['identity'] !== $identityId) {
            continue;
        }
        $running = wt_job_running($id);
        list($exitCode, ) = $running ? [null, null] : wt_job_result($id);
        $out[] = [
            'id'      => $id,
            'command' => mb_strimwidth($meta['command'], 0, 200, '...'),
            'started' => $meta['started'],
            'running' => $running,
            'exit'    => $exitCode,
        ];
    }
    usort($out, function ($a, $b) {
        return $b['started'] <=> $a['started'];
    });
    return array_slice($out, 0, $limit);
}

function wt_job_gc()
{
    // Cheap, probabilistic sweep so we don't stat every file on every request.
    if (mt_rand(1, 10) !== 1) {
        return;
    }
    $now = time();
    foreach (glob(wt_jobs_dir() . '/*.meta') ?: [] as $metaFile) {
        $id   = basename($metaFile, '.meta');
        $meta = wt_job_meta_read($id);
        $p    = wt_job_paths($id);
        if ($meta === null) {
            continue;
        }
        if (wt_job_running($id)) {
            // Auto-kill runaway jobs.
            if ($now - (int) $meta['started'] > TERMINAL_JOB_MAX_RUNTIME) {
                wt_job_kill($id);
                @file_put_contents($p['log'], "\n[auto-killed after " . TERMINAL_JOB_MAX_RUNTIME . "s]\n", FILE_APPEND);
                @file_put_contents($p['exit'], '137', LOCK_EX);
            }
            continue;
        }
        $finishedAt = is_file($p['exit']) ? filemtime($p['exit']) : $meta['started'];
        if ($now - $finishedAt > TERMINAL_JOB_RETENTION) {
            foreach ($p as $f) {
                @unlink($f);
            }
        }
    }
}

// ======================= COMMAND WRAPPER (sync fallback for Windows hosts) =======================
//
// The background-job engine above relies on POSIX shell features (setsid,
// nohup, process groups, traps) and is not portable to Windows. On a Windows
// host every command instead runs synchronously, with a hard timeout, the
// same way the original single-shot version of this script worked. There is
// no `cd` persistence or background-job support in this mode - run this
// script on a Linux/Unix host for the full feature set.

function wt_run_windows_sync($command, $timeoutSeconds, $maxBytes)
{
    return wt_run_proc($command . ' 2>&1', $timeoutSeconds, $maxBytes);
}

// ======================= REQUEST HANDLING =======================

$wtIp = wt_client_ip();
if (TERMINAL_ALLOWED_IPS && !in_array($wtIp, TERMINAL_ALLOWED_IPS, true)) {
    http_response_code(403);
    exit('Forbidden');
}

$wtHttps = wt_is_https();
if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $wtHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
} else {
    session_set_cookie_params(0, '/; samesite=Strict', '', $wtHttps, true);
}
session_name('WTSESS');
session_start();

wt_headers_common();

// ---------------- AJAX / API HANDLER ----------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw   = (string) file_get_contents('php://input');
    $input = json_decode($raw, true);
    if (!is_array($input)) {
        wt_bad_request('Bad request.');
    }
    $action = isset($input['action']) && is_string($input['action']) ? $input['action'] : 'exec';

    // ---- LOGIN (browser password) ----
    if ($action === 'login') {
        if (!wt_password_configured()) {
            wt_json([
                'ok'     => false,
                'output' => "Password is not configured. Set TERMINAL_PASSWORD_HASH in web_terminal.php.\n",
            ], 503);
        }
        $wait = wt_locked_for($wtIp);
        if ($wait > 0) {
            wt_json(['ok' => false, 'output' => "Too many failed attempts. Try again in {$wait} seconds.\n"], 429);
        }
        $pwd = isset($input['password']) && is_string($input['password']) ? $input['password'] : '';
        if (wt_verify_against_hash($pwd, TERMINAL_PASSWORD_HASH)) {
            wt_clear_failures($wtIp);
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            $_SESSION['last'] = time();
            $identityId = 'sess_' . substr(hash('sha256', session_id()), 0, 20);
            wt_audit($identityId, 'login_ok');
            wt_json([
                'ok'        => true,
                'output'    => "Authentication successful.\n",
                'csrf'      => $_SESSION['csrf'],
                'cwd'       => wt_get_cwd($identityId),
                'executor'  => wt_pick_executor(),
                'jobs'      => !wt_is_windows(),
                'dataOk'    => wt_data_writable(),
            ]);
        }
        wt_register_failure($wtIp);
        wt_audit('anon', 'login_fail');
        sleep(1);
        wt_json(['ok' => false, 'output' => "Authentication failed.\n"], 401);
    }

    // Every other action requires either a valid API key or a valid session.
    $identity = wt_authenticate($input);
    if ($identity === null) {
        $wait = wt_locked_for($wtIp);
        if ($wait > 0) {
            wt_json(['ok' => false, 'auth' => false, 'output' => "Too many failed attempts. Try again in {$wait} seconds.\n"], 429);
        }
        $usedApiKey = isset($_SERVER['HTTP_X_API_KEY']) || (isset($input['api_key']) && $input['api_key'] !== '');
        if ($usedApiKey) {
            wt_register_failure($wtIp);
            wt_audit('anon', 'apikey_fail');
        }
        wt_json(['ok' => false, 'auth' => false, 'output' => "Not authenticated. Log in again or check your API key.\n"], 401);
    }
    $identityId = $identity['id'];

    if ($action === 'logout') {
        wt_audit($identityId, 'logout');
        wt_session_destroy();
        wt_json(['ok' => true, 'output' => "Logged out.\n"]);
    }

    wt_job_gc();

    if ($action === 'whoami') {
        wt_json([
            'ok' => true,
            'identity' => $identity['kind'],
            'cwd' => wt_get_cwd($identityId),
            'phpVersion' => PHP_VERSION,
            'os' => PHP_OS,
            'uname' => function_exists('php_uname') ? php_uname() : PHP_OS,
            'serverSoftware' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
            'user' => function_exists('get_current_user') ? get_current_user() : 'unknown',
            'executor' => wt_pick_executor(),
            'backgroundJobs' => !wt_is_windows(),
            'diskFreeBytes' => @disk_free_space(__DIR__),
            'memoryLimit' => ini_get('memory_limit'),
            'dataDirWritable' => wt_data_writable(),
            'auditLog' => TERMINAL_ENABLE_AUDIT_LOG,
            'scriptPath' => __FILE__,
        ]);
    }

    if ($action === 'history') {
        wt_json(['ok' => true, 'history' => wt_history_get($identityId)]);
    }

    if ($action === 'jobs') {
        wt_json(['ok' => true, 'jobs' => wt_job_list($identityId)]);
    }

    if ($action === 'kill') {
        $job = isset($input['job']) && is_string($input['job']) ? $input['job'] : '';
        $meta = $job !== '' ? wt_job_meta_read($job) : null;
        if ($meta === null || $meta['identity'] !== $identityId) {
            wt_bad_request('Unknown job.', 404);
        }
        wt_job_kill($job);
        wt_audit($identityId, 'kill', $job);
        wt_json(['ok' => true, 'output' => "Kill signal sent.\n"]);
    }

    if ($action === 'poll') {
        $job    = isset($input['job']) && is_string($input['job']) ? $input['job'] : '';
        $offset = isset($input['offset']) ? max(0, (int) $input['offset']) : 0;
        $meta   = $job !== '' ? wt_job_meta_read($job) : null;
        if ($meta === null || $meta['identity'] !== $identityId) {
            wt_bad_request('Unknown job.', 404);
        }
        list($chunk, $newOffset) = wt_job_tail($job, $offset, TERMINAL_MAX_OUTPUT);
        $running = wt_job_running($job);
        $resp = [
            'ok'     => true,
            'state'  => $running ? 'running' : 'done',
            'output' => $chunk,
            'offset' => $newOffset,
            'job'    => $job,
        ];
        if (!$running) {
            list($exitCode, $newCwd) = wt_job_result($job);
            $resp['exitCode'] = $exitCode;
            if ($newCwd !== null) {
                wt_set_cwd($identityId, $newCwd);
                $resp['cwd'] = $newCwd;
            }
            wt_audit($identityId, 'exec_done', trim(($meta['command'] ?? '') . ' => ' . $exitCode));
        }
        wt_json($resp);
    }

    if ($action === 'upload') {
        $path = isset($input['path']) && is_string($input['path']) ? trim($input['path']) : '';
        $data = isset($input['data']) && is_string($input['data']) ? $input['data'] : null;
        if ($path === '' || $data === null) {
            wt_bad_request('path and data are required.');
        }
        if (strlen($data) > TERMINAL_MAX_UPLOAD_BYTES * 1.4) {
            wt_bad_request('File too large (limit ~' . round(TERMINAL_MAX_UPLOAD_BYTES / 1048576) . ' MB).', 413);
        }
        $bytes = base64_decode($data, true);
        if ($bytes === false) {
            wt_bad_request('Invalid base64 payload.');
        }
        $cwd = wt_get_cwd($identityId);
        $dest = (strlen($path) > 0 && ($path[0] === '/' || preg_match('#^[A-Za-z]:[\\\\/]#', $path)))
            ? $path
            : rtrim($cwd, '/\\') . DIRECTORY_SEPARATOR . $path;
        $dir = dirname($dest);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $written = @file_put_contents($dest, $bytes, LOCK_EX);
        if ($written === false) {
            wt_json(['ok' => false, 'output' => "Could not write to {$dest}\n"]);
        }
        wt_audit($identityId, 'upload', $dest . ' (' . $written . ' bytes)');
        wt_json(['ok' => true, 'output' => "Uploaded " . $written . " bytes to {$dest}\n", 'path' => $dest]);
    }

    if ($action === 'download') {
        $path = isset($input['path']) && is_string($input['path']) ? trim($input['path']) : '';
        if ($path === '') {
            wt_bad_request('path is required.');
        }
        $cwd = wt_get_cwd($identityId);
        $src = (strlen($path) > 0 && ($path[0] === '/' || preg_match('#^[A-Za-z]:[\\\\/]#', $path)))
            ? $path
            : rtrim($cwd, '/\\') . DIRECTORY_SEPARATOR . $path;
        if (!is_file($src) || !is_readable($src)) {
            wt_bad_request('File not found or not readable: ' . $src, 404);
        }
        $size = filesize($src);
        if ($size > TERMINAL_MAX_UPLOAD_BYTES * 4) {
            wt_bad_request('File too large to download through this endpoint.', 413);
        }
        wt_audit($identityId, 'download', $src . ' (' . $size . ' bytes)');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($src) . '"');
        header('Content-Length: ' . $size);
        header('Content-Security-Policy: sandbox');
        readfile($src);
        exit;
    }

    // ---- EXEC ----
    if ($action !== 'exec') {
        wt_bad_request('Unknown action.');
    }

    $command = isset($input['command']) && is_string($input['command']) ? trim($input['command']) : '';
    if ($command === '') {
        wt_json(['ok' => false, 'output' => "No command provided.\n"]);
    }
    if (strlen($command) > TERMINAL_MAX_COMMAND_LEN) {
        wt_bad_request('Command too long.');
    }
    if (wt_pick_executor() === null) {
        wt_json([
            'ok'     => false,
            'output' => "This host has disabled every PHP command-execution function "
                . "(" . implode(', ', wt_executors()) . ").\n",
        ]);
    }

    $cwd = wt_get_cwd($identityId);
    wt_history_add($identityId, $command);

    if (wt_is_windows()) {
        // No portable backgrounding on Windows: run synchronously with a hard
        // timeout, and no `cd` persistence (see the note above wt_run_windows_sync).
        @set_time_limit(TERMINAL_COMMAND_TIMEOUT + 10);
        $outRaw = wt_run_windows_sync($command, TERMINAL_COMMAND_TIMEOUT, TERMINAL_MAX_OUTPUT);
        if ($outRaw === null) {
            wt_json(['ok' => false, 'output' => "Could not start the command on this host.\n"]);
        }
        wt_audit($identityId, 'exec_done', $command);
        $outRaw = rtrim($outRaw, "\r\n");
        wt_json([
            'ok'       => true,
            'state'    => 'done',
            'output'   => $outRaw === '' ? '' : $outRaw . "\n",
            'exitCode' => null,
            'cwd'      => $cwd,
            'offset'   => 0,
            'job'      => null,
        ]);
    }

    $jobId = wt_job_start($command, $cwd, $identityId);
    if ($jobId === null) {
        wt_json(['ok' => false, 'output' => "Could not start the command on this host.\n"]);
    }

    // Give fast commands a short grace period so the UI feels instant; slow
    // ones fall through and the client switches to polling.
    $deadline = microtime(true) + (TERMINAL_SYNC_GRACE_MS / 1000);
    while (microtime(true) < $deadline) {
        if (!wt_job_running($jobId)) {
            break;
        }
        usleep(80000);
    }

    list($chunk, $offset) = wt_job_tail($jobId, 0, TERMINAL_MAX_OUTPUT);
    if (!wt_job_running($jobId)) {
        list($exitCode, $newCwd) = wt_job_result($jobId);
        if ($newCwd !== null) {
            wt_set_cwd($identityId, $newCwd);
        }
        wt_audit($identityId, 'exec_done', trim($command . ' => ' . $exitCode));
        wt_json([
            'ok'       => ($exitCode === 0),
            'state'    => 'done',
            'output'   => $chunk,
            'exitCode' => $exitCode,
            'cwd'      => $newCwd !== null ? $newCwd : $cwd,
            'offset'   => $offset,
            'job'      => $jobId,
        ]);
    }

    wt_json([
        'ok'     => true,
        'state'  => 'running',
        'output' => $chunk,
        'offset' => $offset,
        'job'    => $jobId,
        'cwd'    => $cwd,
    ]);
}

// ---------------- PAGE (GET) ----------------
$wtAuthed = wt_session_valid();
$wtIdentityId = $wtAuthed ? ('sess_' . substr(hash('sha256', session_id()), 0, 20)) : '';
$wtBoot = [
    'authed'      => $wtAuthed,
    'csrf'        => $wtAuthed ? $_SESSION['csrf'] : '',
    'cwd'         => $wtAuthed ? wt_get_cwd($wtIdentityId) : '',
    'https'       => $wtHttps,
    'configured'  => wt_password_configured(),
    'apiKey'      => wt_api_key_configured(),
    'jobs'        => !wt_is_windows(),
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Web Terminal</title>
    <style>
        :root {
            --bg: #0e101a;
            --panel: #1a1c29;
            --panel2: #2e3047;
            --out-bg: #141622;
            --text: #f5f5f5;
            --muted: #9da5b4;
            --dim: #6a75a1;
            --border: #3d415c;
            --accent: #4a5fc1;
            --accent-hover: #3d51a3;
            --err: #ff6c6c;
            --ok: #6cffa0;
        }
        [data-theme="light"] {
            --bg: #eef0f5;
            --panel: #ffffff;
            --panel2: #e6e8f0;
            --out-bg: #fafbfe;
            --text: #1b1d27;
            --muted: #555b6e;
            --dim: #7a82a0;
            --border: #cfd3e4;
            --accent: #4a5fc1;
            --accent-hover: #3d51a3;
            --err: #c23b3b;
            --ok: #1f9a53;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            padding: 0;
            background: var(--bg);
            color: var(--text);
            font-family: 'Courier New', monospace;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .terminal-container {
            width: 95%;
            max-width: 1100px;
            height: 88vh;
            background: var(--panel);
            border-radius: 8px;
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            position: relative;
        }
        .terminal-header {
            padding: 10px 15px;
            background: var(--panel2);
            color: var(--muted);
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 14px;
            flex-wrap: wrap;
            gap: 6px;
        }
        .terminal-header .title { font-weight: bold; color: var(--text); }
        .right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .icon-btn {
            background: transparent;
            color: var(--muted);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 3px 8px;
            font-family: inherit;
            font-size: 12px;
            cursor: pointer;
        }
        .icon-btn:hover { color: var(--text); border-color: var(--accent); }
        .icon-btn.danger:hover { color: var(--err); border-color: var(--err); }
        .logout-btn { display: none; }
        .panels { display: none; border-bottom: 1px solid var(--border); background: var(--out-bg); max-height: 40%; overflow-y: auto; }
        .panels.open { display: block; }
        .panel { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 12.5px; }
        .panel h4 { margin: 0 0 6px; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
        .panel table { width: 100%; border-collapse: collapse; }
        .panel td { padding: 2px 6px 2px 0; vertical-align: top; color: var(--text); }
        .panel td.k { color: var(--dim); white-space: nowrap; padding-right: 10px; }
        .job-row { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 4px 0; border-bottom: 1px dashed var(--border); }
        .job-row:last-child { border-bottom: none; }
        .job-cmd { font-size: 12px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
        .job-status { font-size: 11px; padding: 1px 6px; border-radius: 10px; border: 1px solid var(--border); }
        .job-status.running { color: var(--ok); border-color: var(--ok); }
        .job-row .icon-btn { padding: 1px 6px; font-size: 11px; }
        .terminal-output {
            flex: 1;
            padding: 10px;
            overflow-y: auto;
            background: var(--out-bg);
            color: var(--text);
            font-size: 14px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .terminal-output .err { color: var(--err); }
        .terminal-output .ok { color: var(--ok); }
        .terminal-output .sys { color: var(--dim); }
        .runbar { display: none; align-items: center; gap: 8px; padding: 6px 12px; background: var(--panel2); border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); }
        .runbar.show { display: flex; }
        .spinner { width: 10px; height: 10px; border-radius: 50%; border: 2px solid var(--border); border-top-color: var(--accent); animation: spin .8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .terminal-input {
            display: flex;
            padding: 10px;
            background: var(--panel2);
            border-top: 1px solid var(--border);
            align-items: center;
        }
        .terminal-input .prompt {
            margin-right: 8px;
            color: var(--dim);
            user-select: none;
            max-width: 42%;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            direction: rtl;
            text-align: left;
        }
        .terminal-input input {
            flex: 1;
            min-width: 0;
            background: transparent;
            border: none;
            outline: none;
            color: var(--text);
            font-family: inherit;
            font-size: 14px;
        }
        .drop-hint { display: none; position: absolute; inset: 0; background: rgba(74,95,193,.15); border: 2px dashed var(--accent); align-items: center; justify-content: center; font-size: 18px; color: var(--text); pointer-events: none; z-index: 5; }
        .drop-hint.show { display: flex; }
        .login-overlay {
            position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex; justify-content: center; align-items: center;
        }
        .login-box {
            background: var(--panel);
            border-radius: 6px;
            padding: 20px 30px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
            display: flex; flex-direction: column; gap: 10px;
            width: 320px; max-width: 80%;
        }
        .login-box h2 { margin: 0 0 10px 0; color: var(--text); font-size: 20px; text-align: center; }
        .login-box input[type="password"] { padding: 8px; border-radius: 4px; border: none; outline: none; font-size: 14px; }
        .login-box button { padding: 8px; border-radius: 4px; border: none; background: var(--accent); color: #fff; font-weight: bold; cursor: pointer; transition: background .2s ease; }
        .login-box button:hover { background: var(--accent-hover); }
        .login-box button:disabled { opacity: .6; cursor: default; }
        .login-error { color: var(--err); font-size: 13px; display: none; }
        .login-hint { color: var(--muted); font-size: 12px; display: none; text-align: center; }
        .terminal-footer {
            padding: 8px 12px; background: var(--panel2); color: var(--muted);
            font-size: 13px; text-align: right; border-top: 1px solid var(--border); user-select: none;
        }
        .terminal-footer a { color: #8fb1ff; text-decoration: none; font-weight: 600; }
        .terminal-footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="terminal-container" id="container">
    <div class="terminal-header">
        <div class="title">Web Terminal</div>
        <div class="right">
            <button class="icon-btn" id="infoBtn" type="button" title="System info">Info</button>
            <button class="icon-btn" id="jobsBtn" type="button" title="Background jobs">Jobs</button>
            <button class="icon-btn" id="uploadBtn" type="button" title="Upload a file">Upload</button>
            <button class="icon-btn" id="themeBtn" type="button" title="Toggle theme">Theme</button>
            <button class="icon-btn" id="fontMinus" type="button" title="Smaller text">A-</button>
            <button class="icon-btn" id="fontPlus" type="button" title="Larger text">A+</button>
            <div class="status" id="statusText">Not Authenticated</div>
            <button class="icon-btn danger logout-btn" id="logoutBtn" type="button">Logout</button>
        </div>
    </div>
    <div class="panels" id="panels"></div>
    <div id="terminalOutput" class="terminal-output"></div>
    <div class="runbar" id="runbar">
        <span class="spinner"></span>
        <span id="runbarText">Running...</span>
        <button class="icon-btn danger" id="killBtn" type="button" style="margin-left:auto;">Kill</button>
    </div>
    <div class="terminal-input">
        <span class="prompt" id="promptEl">$</span>
        <input type="text" id="commandInput" placeholder="Type a command... (try: help)" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" disabled />
    </div>
    <input type="file" id="fileInput" style="display:none" multiple />
    <div class="drop-hint" id="dropHint">Drop file to upload to the current directory</div>
    <div class="login-overlay" id="loginOverlay">
        <div class="login-box">
            <h2>Login</h2>
            <input type="password" id="loginPassword" placeholder="Enter password" autocomplete="current-password" autofocus />
            <button id="loginButton" type="button">Login</button>
            <div class="login-error" id="loginError"></div>
            <div class="login-hint" id="loginHint"></div>
        </div>
    </div>
    <footer class="terminal-footer">Built with ❤️ in Bangladesh by <a href="https://iamnaime.info.bd" target="_blank" rel="noopener noreferrer">Fattain Naime</a></footer>
</div>

<script>
(function () {
    const BOOT = <?php echo json_encode($wtBoot, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;

    const el = (id) => document.getElementById(id);
    const outputEl = el('terminalOutput');
    const cmdInput = el('commandInput');
    const statusText = el('statusText');
    const promptEl = el('promptEl');
    const logoutBtn = el('logoutBtn');
    const panelsEl = el('panels');
    const runbar = el('runbar');
    const runbarText = el('runbarText');
    const killBtn = el('killBtn');
    const dropHint = el('dropHint');
    const fileInput = el('fileInput');
    const container = el('container');

    const loginOverlay = el('loginOverlay');
    const loginButton  = el('loginButton');
    const loginPassword = el('loginPassword');
    const loginError   = el('loginError');
    const loginHint    = el('loginHint');

    let csrf = BOOT.csrf || '';
    let cwd = BOOT.cwd || '';
    let authed = false;
    let busy = false;
    let currentJob = null;
    let pollTimer = null;
    let history = [];
    let historyIndex = -1;

    try {
        const savedTheme = localStorage.getItem('wt_theme');
        if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
        const savedSize = localStorage.getItem('wt_fontsize');
        if (savedSize) outputEl.style.fontSize = cmdInput.style.fontSize = savedSize + 'px';
    } catch (e) { /* storage may be unavailable */ }

    function escapeHtml(s) {
        return s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    }
    function appendOutput(text, cls) {
        if (!text) return;
        if (cls) {
            const span = document.createElement('span');
            span.className = cls;
            span.textContent = text;
            outputEl.appendChild(span);
        } else {
            outputEl.appendChild(document.createTextNode(text));
        }
        outputEl.scrollTop = outputEl.scrollHeight;
    }

    // ---- ANSI color support for command output ----
    // Renders common SGR color/style codes (as produced by `ls --color`,
    // `git -c color.ui=always`, colored test runners, etc.) as real colors
    // instead of raw escape garbage. Cursor-movement/clear-screen/OSC
    // sequences are recognized and silently dropped (this is a scrollback
    // log, not a full terminal emulator, so they have nothing to do here).
    const ANSI_FG = {
        30: '#2e2e2e', 31: '#e5534b', 32: '#3fb950', 33: '#d4a72c', 34: '#539bf5',
        35: '#bc8cff', 36: '#56d4dd', 37: '#d0d7de',
        90: '#6e7681', 91: '#ff7b72', 92: '#56d364', 93: '#e3b341', 94: '#79c0ff',
        95: '#d2a8ff', 96: '#76e3ea', 97: '#ffffff',
    };
    const ANSI_BG = {
        40: '#2e2e2e', 41: '#e5534b', 42: '#3fb950', 43: '#d4a72c', 44: '#539bf5',
        45: '#bc8cff', 46: '#56d4dd', 47: '#d0d7de',
        100: '#6e7681', 101: '#ff7b72', 102: '#56d364', 103: '#e3b341', 104: '#79c0ff',
        105: '#d2a8ff', 106: '#76e3ea', 107: '#ffffff',
    };
    function ansiToSegments(input) {
        const re = /\x1b\[([0-9;]*)m|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][0-9A-Za-z]|\r/g;
        let state = { bold: false, dim: false, italic: false, underline: false, fg: null, bg: null };
        const segments = [];
        let last = 0, m;
        const pushText = (text) => { if (text) segments.push({ text, style: Object.assign({}, state) }); };
        while ((m = re.exec(input)) !== null) {
            pushText(input.slice(last, m.index));
            last = re.lastIndex;
            const sgr = m[1];
            if (sgr === undefined) continue; // non-color escape: drop
            const codes = sgr === '' ? [0] : sgr.split(';').map((n) => parseInt(n, 10));
            for (let i = 0; i < codes.length; i++) {
                const c = codes[i];
                if (c === 0 || Number.isNaN(c)) state = { bold: false, dim: false, italic: false, underline: false, fg: null, bg: null };
                else if (c === 1) state.bold = true;
                else if (c === 2) state.dim = true;
                else if (c === 3) state.italic = true;
                else if (c === 4) state.underline = true;
                else if (c === 22) { state.bold = false; state.dim = false; }
                else if (c === 23) state.italic = false;
                else if (c === 24) state.underline = false;
                else if (c === 39) state.fg = null;
                else if (c === 49) state.bg = null;
                else if (ANSI_FG[c] !== undefined) state.fg = ANSI_FG[c];
                else if (ANSI_BG[c] !== undefined) state.bg = ANSI_BG[c];
                else if (c === 38 || c === 48) {
                    const target = c === 38 ? 'fg' : 'bg';
                    const mode = codes[i + 1];
                    if (mode === 5) { i += 2; }
                    else if (mode === 2) {
                        const r = codes[i + 2], g = codes[i + 3], b = codes[i + 4];
                        if ([r, g, b].every((v) => Number.isInteger(v))) state[target] = 'rgb(' + r + ',' + g + ',' + b + ')';
                        i += 4;
                    }
                }
            }
        }
        pushText(input.slice(last));
        return segments;
    }
    function appendCommandOutput(text) {
        if (!text) return;
        const frag = document.createDocumentFragment();
        for (const seg of ansiToSegments(text)) {
            const st = seg.style;
            if (!st.bold && !st.dim && !st.italic && !st.underline && !st.fg && !st.bg) {
                frag.appendChild(document.createTextNode(seg.text));
                continue;
            }
            const span = document.createElement('span');
            span.textContent = seg.text;
            let css = '';
            if (st.fg) css += 'color:' + st.fg + ';';
            if (st.bg) css += 'background:' + st.bg + ';';
            if (st.bold) css += 'font-weight:bold;';
            if (st.dim) css += 'opacity:.7;';
            if (st.italic) css += 'font-style:italic;';
            if (st.underline) css += 'text-decoration:underline;';
            span.style.cssText = css;
            frag.appendChild(span);
        }
        outputEl.appendChild(frag);
        outputEl.scrollTop = outputEl.scrollHeight;
    }

    function promptText() { return (cwd || '~') + ' $'; }
    function updatePrompt() { promptEl.textContent = promptText(); promptEl.title = cwd; }

    function enterTerminal() {
        authed = true;
        loginOverlay.style.display = 'none';
        cmdInput.disabled = false;
        logoutBtn.style.display = 'inline-block';
        statusText.textContent = 'Authenticated';
        updatePrompt();
        cmdInput.focus();
        if (window.__wtAutoCmd) { const c = window.__wtAutoCmd; window.__wtAutoCmd = null; runCommand(c); }
    }

    function leaveTerminal(message) {
        authed = false;
        csrf = '';
        cwd = '';
        stopPolling();
        currentJob = null;
        cmdInput.disabled = true;
        cmdInput.value = '';
        logoutBtn.style.display = 'none';
        statusText.textContent = 'Not Authenticated';
        loginOverlay.style.display = 'flex';
        loginPassword.value = '';
        loginPassword.focus();
        updatePrompt();
        if (message) appendOutput(message, 'err');
    }

    async function api(payload) {
        const headers = { 'Content-Type': 'application/json' };
        if (csrf) headers['X-CSRF-Token'] = csrf;
        const res = await fetch(window.location.href, {
            method: 'POST', headers, credentials: 'same-origin', body: JSON.stringify(payload)
        });
        let data;
        try { data = await res.json(); }
        catch (e) { data = { ok: false, output: 'Unexpected server response (HTTP ' + res.status + ').\n' }; }
        data.httpStatus = res.status;
        return data;
    }

    function showLoginError(text) { loginError.textContent = text; loginError.style.display = 'block'; }

    async function performLogin() {
        const pwd = loginPassword.value;
        if (!pwd || loginButton.disabled) return;
        loginButton.disabled = true;
        loginError.style.display = 'none';
        try {
            const data = await api({ action: 'login', password: pwd });
            if (data.ok) {
                csrf = data.csrf; cwd = data.cwd;
                loginPassword.value = '';
                let note = 'Web Terminal Pro - type "help" for tips.\n';
                if (data.executor) note += 'Executor: ' + data.executor + (data.jobs ? ' (background jobs enabled)' : ' (sync only on this host)') + '\n';
                if (!data.dataOk) note += 'WARNING: data directory is not writable - jobs/history/uploads may fail.\n';
                appendOutput(note + '\n', 'sys');
                enterTerminal();
            } else {
                showLoginError((data.output || 'Authentication failed.').trim());
                loginPassword.value = '';
                loginPassword.focus();
            }
        } catch (e) {
            showLoginError('Error contacting server.');
        } finally {
            loginButton.disabled = false;
        }
    }

    async function performLogout() {
        try { await api({ action: 'logout' }); } catch (e) {}
        leaveTerminal('Logged out.\n');
    }

    loginButton.addEventListener('click', performLogin);
    loginPassword.addEventListener('keydown', (e) => { if (e.key === 'Enter') performLogin(); });
    logoutBtn.addEventListener('click', performLogout);
    if (!BOOT.configured) {
        loginHint.textContent = 'No password configured yet - set TERMINAL_PASSWORD_HASH in web_terminal.php.';
        loginHint.style.display = 'block';
    }

    function setRunning(isRunning, label) {
        runbar.classList.toggle('show', isRunning);
        if (label) runbarText.textContent = label;
        cmdInput.disabled = isRunning || !authed;
        if (!isRunning && authed) cmdInput.focus();
    }

    function stopPolling() {
        if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    }

    async function pollJob(jobId, offset) {
        if (!authed) return;
        const data = await api({ action: 'poll', job: jobId, offset: offset });
        if (data.httpStatus === 401) { leaveTerminal(data.output || 'Session expired.\n'); return; }
        appendCommandOutput(data.output || '');
        offset = data.offset;
        if (data.state === 'done') {
            currentJob = null;
            setRunning(false);
            if (data.cwd) { cwd = data.cwd; updatePrompt(); }
            if (data.exitCode !== null && data.exitCode !== undefined && data.exitCode !== 0) {
                appendOutput('(exit code: ' + data.exitCode + ')\n', 'err');
            }
            return;
        }
        pollTimer = setTimeout(() => pollJob(jobId, offset), 700);
    }

    async function doKill() {
        if (!currentJob) return;
        await api({ action: 'kill', job: currentJob });
        appendOutput('\n[kill signal sent]\n', 'sys');
    }
    killBtn.addEventListener('click', doKill);

    function clientSideCommand(cmd) {
        const parts = cmd.trim().split(/\s+/);
        const name = parts[0];
        if (name === 'clear') { outputEl.textContent = ''; return true; }
        if (name === 'exit' || name === 'logout') { performLogout(); return true; }
        if (name === 'help') {
            appendOutput(
                'Built-in: clear, exit, help, theme, upload, download <path>, jobs, history\n' +
                'Real shell commands (ls, pwd, git, php, composer, ...) run on the server.\n' +
                'Long-running commands become a background job automatically - watch the status bar.\n' +
                'This same server also has a CLI client: see webterm_client.py in the repo.\n\n',
                'sys'
            );
            return true;
        }
        if (name === 'theme') { toggleTheme(); return true; }
        if (name === 'upload') { fileInput.click(); return true; }
        if (name === 'jobs') { togglePanel('jobs'); return true; }
        if (name === 'download' && parts[1]) { triggerDownload(parts.slice(1).join(' ')); return true; }
        return false;
    }

    async function runCommand(command) {
        const cmd = command.trim();
        if (!cmd) return;
        if (clientSideCommand(cmd)) return;
        appendOutput(promptText() + ' ' + command + '\n');
        busy = true;
        setRunning(true, 'Running...');
        try {
            const data = await api({ action: 'exec', command: cmd });
            if (data.httpStatus === 401) { leaveTerminal(data.output || 'Session expired.\n'); return; }
            appendCommandOutput(data.output || '');
            if (data.cwd) { cwd = data.cwd; updatePrompt(); }
            if (data.state === 'running' && data.job) {
                currentJob = data.job;
                setRunning(true, 'Running in background (job ' + data.job.slice(0, 8) + ')...');
                pollTimer = setTimeout(() => pollJob(data.job, data.offset || 0), 700);
                return;
            }
            setRunning(false);
            if (data.exitCode !== null && data.exitCode !== undefined && data.exitCode !== 0) {
                appendOutput('(exit code: ' + data.exitCode + ')\n', 'err');
            }
        } catch (e) {
            appendOutput('Error contacting server.\n', 'err');
            setRunning(false);
        } finally {
            busy = false;
        }
    }

    cmdInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            if (busy) return;
            const cmd = cmdInput.value;
            if (cmd.trim() && history[history.length - 1] !== cmd) history.push(cmd);
            historyIndex = history.length;
            cmdInput.value = '';
            runCommand(cmd);
        } else if (e.key === 'l' && e.ctrlKey) {
            e.preventDefault(); outputEl.textContent = '';
        } else if (e.key === 'c' && e.ctrlKey && currentJob) {
            e.preventDefault(); doKill();
        } else if (e.key === 'ArrowUp') {
            if (historyIndex > 0) { historyIndex--; cmdInput.value = history[historyIndex] || ''; setTimeout(() => cmdInput.setSelectionRange(cmdInput.value.length, cmdInput.value.length), 0); }
            e.preventDefault();
        } else if (e.key === 'ArrowDown') {
            if (historyIndex < history.length - 1) { historyIndex++; cmdInput.value = history[historyIndex] || ''; }
            else { historyIndex = history.length; cmdInput.value = ''; }
            e.preventDefault();
        }
    });

    document.addEventListener('click', () => {
        if (cmdInput.disabled) return;
        const sel = window.getSelection ? window.getSelection().toString() : '';
        if (!sel) cmdInput.focus();
    });

    // ---- Theme / font size ----
    function toggleTheme() {
        const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', cur);
        try { localStorage.setItem('wt_theme', cur); } catch (e) {}
    }
    el('themeBtn').addEventListener('click', toggleTheme);
    function adjustFont(delta) {
        const cur = parseInt(window.getComputedStyle(outputEl).fontSize, 10) || 14;
        const next = Math.max(10, Math.min(24, cur + delta));
        outputEl.style.fontSize = cmdInput.style.fontSize = next + 'px';
        try { localStorage.setItem('wt_fontsize', next); } catch (e) {}
    }
    el('fontPlus').addEventListener('click', () => adjustFont(1));
    el('fontMinus').addEventListener('click', () => adjustFont(-1));

    // ---- Panels: info / jobs ----
    let openPanel = null;
    async function togglePanel(name) {
        if (openPanel === name) { panelsEl.classList.remove('open'); panelsEl.innerHTML = ''; openPanel = null; return; }
        openPanel = name;
        panelsEl.classList.add('open');
        panelsEl.innerHTML = '<div class="panel">Loading...</div>';
        if (name === 'info') {
            const d = await api({ action: 'whoami' });
            const rows = [
                ['Identity', d.identity], ['Working dir', d.cwd], ['PHP', d.phpVersion], ['OS', d.uname || d.os],
                ['Server', d.serverSoftware], ['Executor', d.executor], ['Background jobs', d.backgroundJobs ? 'yes' : 'no (Windows host)'],
                ['Memory limit', d.memoryLimit], ['Disk free', d.diskFreeBytes ? Math.round(d.diskFreeBytes / 1048576) + ' MB' : 'n/a'],
                ['Data dir writable', d.dataDirWritable ? 'yes' : 'no'], ['Audit log', d.auditLog ? 'on' : 'off'],
            ];
            panelsEl.innerHTML = '<div class="panel"><h4>System info</h4><table>' +
                rows.map(r => '<tr><td class="k">' + r[0] + '</td><td>' + escapeHtml(String(r[1])) + '</td></tr>').join('') +
                '</table></div>';
        } else if (name === 'jobs') {
            await refreshJobs();
        }
    }
    async function refreshJobs() {
        const d = await api({ action: 'jobs' });
        const jobs = d.jobs || [];
        let html = '<div class="panel"><h4>Background jobs</h4>';
        if (!jobs.length) html += '<div class="sys" style="color:var(--dim)">No jobs yet.</div>';
        jobs.forEach(j => {
            html += '<div class="job-row"><span class="job-cmd" title="' + escapeHtml(j.command) + '">' + escapeHtml(j.command) + '</span>' +
                '<span class="job-status' + (j.running ? ' running' : '') + '">' + (j.running ? 'running' : 'exit ' + j.exit) + '</span>' +
                (j.running ? '<button class="icon-btn danger" data-kill="' + j.id + '">kill</button>' : '<button class="icon-btn" data-attach="' + j.id + '">view</button>') +
                '</div>';
        });
        html += '</div>';
        panelsEl.innerHTML = html;
        panelsEl.querySelectorAll('[data-kill]').forEach(b => b.addEventListener('click', async () => {
            await api({ action: 'kill', job: b.getAttribute('data-kill') });
            refreshJobs();
        }));
        panelsEl.querySelectorAll('[data-attach]').forEach(b => b.addEventListener('click', () => {
            const id = b.getAttribute('data-attach');
            appendOutput('\n[attaching to job ' + id.slice(0, 8) + ']\n', 'sys');
            currentJob = id; setRunning(true, 'Streaming job ' + id.slice(0, 8) + '...');
            pollTimer = setTimeout(() => pollJob(id, 0), 50);
        }));
    }
    el('infoBtn').addEventListener('click', () => togglePanel('info'));
    el('jobsBtn').addEventListener('click', () => togglePanel('jobs'));

    // ---- Upload / download ----
    function fileToBase64(file) {
        return new Promise((resolve, reject) => {
            const r = new FileReader();
            r.onload = () => resolve(r.result.split(',')[1] || '');
            r.onerror = reject;
            r.readAsDataURL(file);
        });
    }
    async function uploadFile(file) {
        appendOutput('Uploading ' + file.name + ' (' + file.size + ' bytes)...\n', 'sys');
        try {
            const b64 = await fileToBase64(file);
            const data = await api({ action: 'upload', path: file.name, data: b64 });
            appendOutput((data.output || (data.ok ? 'Done.\n' : 'Upload failed.\n')), data.ok ? 'ok' : 'err');
        } catch (e) { appendOutput('Upload failed.\n', 'err'); }
    }
    el('uploadBtn').addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => { Array.from(fileInput.files).forEach(uploadFile); fileInput.value = ''; });
    ['dragenter', 'dragover'].forEach(ev => container.addEventListener(ev, (e) => { if (!authed) return; e.preventDefault(); dropHint.classList.add('show'); }));
    ['dragleave', 'drop'].forEach(ev => container.addEventListener(ev, (e) => { e.preventDefault(); dropHint.classList.remove('show'); }));
    container.addEventListener('drop', (e) => {
        if (!authed || !e.dataTransfer || !e.dataTransfer.files.length) return;
        Array.from(e.dataTransfer.files).forEach(uploadFile);
    });
    async function triggerDownload(path) {
        appendOutput('Downloading ' + path + '...\n', 'sys');
        const headers = { 'Content-Type': 'application/json' };
        if (csrf) headers['X-CSRF-Token'] = csrf;
        const res = await fetch(window.location.href, { method: 'POST', headers, credentials: 'same-origin', body: JSON.stringify({ action: 'download', path: path }) });
        if (!res.ok) {
            let msg = 'Download failed.';
            try { msg = (await res.json()).output || msg; } catch (e) {}
            appendOutput(msg + '\n', 'err');
            return;
        }
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = path.split('/').pop().split('\\').pop() || 'download';
        document.body.appendChild(a); a.click(); a.remove();
        appendOutput('Saved.\n', 'ok');
    }

    // Initial greeting
    appendOutput('Web Terminal Pro - type commands after login. Type "help" once logged in.\n', 'sys');
    if (!BOOT.https) appendOutput('WARNING: this page is not served over HTTPS. Credentials and commands can be intercepted.\n', 'err');
    if (!BOOT.configured) appendOutput('Setup required: set TERMINAL_PASSWORD_HASH in web_terminal.php (see README).\n', 'err');
    if (!BOOT.apiKey) appendOutput('Tip: set TERMINAL_API_KEY_HASH to also use the CLI client (webterm_client.py).\n', 'sys');
    appendOutput('\n');

    if (BOOT.authed) enterTerminal();
})();
</script>
</body>
</html>
