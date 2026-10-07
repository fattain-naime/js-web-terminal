<?php
/*
 * Simple web terminal with login and command execution.
 *
 * @ Author Fattain Naime
 * @ Website: https://iamnaime.info.bd
 * @ Github: https://github.com/fattain-naime/js-web-terminal
 * @ License: GPL-2.0
 *
 * Enable terminal access where terminal access is forbidden.
 *
 * SETUP: set TERMINAL_PASSWORD_HASH below to a bcrypt hash of your password.
 * Generate one with:
 *     php -r "echo password_hash('your-password', PASSWORD_DEFAULT), PHP_EOL;"
 * The terminal refuses to log anyone in until a hash is configured.
 */

error_reporting(E_ALL);
// Never leak paths or warnings to the browser. Errors go to the server log.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// ======================= CONFIGURATION =======================

// bcrypt hash of your password (see SETUP above). Empty = login disabled.
// A legacy 32-char MD5 hash still works, but bcrypt is strongly recommended.
// Default: 123456
const TERMINAL_PASSWORD_HASH = '$2a$12$PO/q7ZErOGBSFpYd7ZEB3.gJepImc8XuNS0jH7xWTTcWByrzcYTiK';

// Optional IP allow-list, e.g. ['203.0.113.10', '2001:db8::1']. Empty = allow all.
const TERMINAL_ALLOWED_IPS = [];

const TERMINAL_MAX_ATTEMPTS    = 5;        // failed logins before lockout
const TERMINAL_LOCKOUT_SECONDS = 300;      // lockout duration (per IP)
const TERMINAL_IDLE_TIMEOUT    = 1800;     // auto-logout after inactivity (seconds)
const TERMINAL_COMMAND_TIMEOUT = 60;       // max seconds per command (proc_open only)
const TERMINAL_MAX_OUTPUT      = 1048576;  // max output bytes returned per command
const TERMINAL_MAX_COMMAND_LEN = 16384;

// ======================= HELPERS =======================

function wt_is_https()
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
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

function wt_hash_configured()
{
    $h = TERMINAL_PASSWORD_HASH;
    // Refuse the old published default ("123") as well.
    return $h !== '' && strtolower($h) !== '202cb962ac59075b964b07152d234b70';
}

function wt_verify_password($pwd)
{
    if (!wt_hash_configured() || $pwd === '') {
        return false;
    }
    $h = TERMINAL_PASSWORD_HASH;
    if (preg_match('/^[a-f0-9]{32}$/i', $h)) {
        return hash_equals(strtolower($h), md5($pwd)); // legacy MD5, constant-time compare
    }
    return password_verify($pwd, $h);
}

// ---- Brute-force protection (per IP, stored in the system temp dir) ----

function wt_lock_file($ip)
{
    return rtrim(sys_get_temp_dir(), '/\\') . '/wt_' . hash('sha256', $ip . __FILE__) . '.json';
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

// ---- Session ----

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

function wt_require_auth()
{
    if (!wt_session_valid()) {
        wt_session_destroy();
        wt_json(['ok' => false, 'auth' => false, 'output' => "Session expired. Please log in again.\n"], 401);
    }
    $token = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? (string) $_SERVER['HTTP_X_CSRF_TOKEN'] : '';
    if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token)) {
        wt_json(['ok' => false, 'output' => "Invalid security token. Reload the page.\n"], 403);
    }
    $_SESSION['last'] = time();
}

// ---- Command execution (works on hosts that disable some functions) ----

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
function wt_run_proc($script)
{
    $windows = DIRECTORY_SEPARATOR === '\\';
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
        if (strlen($out) > TERMINAL_MAX_OUTPUT) {
            @proc_terminate($proc, 9);
            $out = substr($out, 0, TERMINAL_MAX_OUTPUT) . "\n[output truncated]\n";
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
        if (time() - $start >= TERMINAL_COMMAND_TIMEOUT) {
            @proc_terminate($proc, 9);
            $out .= "\n[timed out after " . TERMINAL_COMMAND_TIMEOUT . "s]\n";
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

/** Run $script with the first usable function. Returns [output, functionName] or null. */
function wt_run($script)
{
    foreach (wt_executors() as $fn) {
        if (!wt_fn_enabled($fn)) {
            continue;
        }
        $out = null; // null = could not start, try the next function
        switch ($fn) {
            case 'proc_open':
                $out = wt_run_proc($script);
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
                $out = ($r === false) ? null : (string) $r;
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
                        if (strlen($out) > TERMINAL_MAX_OUTPUT) {
                            $out = substr($out, 0, TERMINAL_MAX_OUTPUT) . "\n[output truncated]\n";
                            break;
                        }
                    }
                    pclose($h);
                }
                break;
        }
        if (is_string($out)) {
            return [$out, $fn];
        }
    }
    return null;
}

/**
 * Wrap the user's command so that stderr is merged, stdin is closed (no hanging on
 * prompts), the working directory persists between commands and the exit code is
 * reported back in a marker line.
 */
function wt_build_script($command, $cwd, $marker)
{
    if (DIRECTORY_SEPARATOR === '\\') {
        return $command . ' 2>&1';
    }
    return "exec 2>&1 < /dev/null\n"
        . 'cd ' . escapeshellarg($cwd) . " 2>/dev/null\n"
        . $command . "\n\n"
        . "__wt_rc=\$?\n"
        . 'printf ' . escapeshellarg("\n" . $marker . ':%s:%s') . ' "$__wt_rc" "$(pwd)"' . "\n";
}

/** Split the marker off the output. Returns [cleanOutput, exitCode|null, newCwd]. */
function wt_parse_output($raw, $marker, $oldCwd)
{
    $rc  = null;
    $cwd = $oldCwd;
    $key = "\n" . $marker . ':';
    $pos = strrpos($raw, $key);
    if ($pos !== false) {
        $tail = substr($raw, $pos + strlen($key));
        $raw  = substr($raw, 0, $pos);
        if (preg_match('/^(\d*):(.*)$/s', $tail, $m)) {
            $rc = ($m[1] === '') ? null : (int) $m[1];
            $p  = trim($m[2]);
            if ($p !== '' && strlen($p) < 4096) {
                $cwd = $p;
            }
        }
    }
    return [$raw, $rc, $cwd];
}

// ======================= REQUEST HANDLING =======================

$wtIp = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
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

// ---------------- AJAX HANDLER ----------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode((string) file_get_contents('php://input'), true);
    if (!is_array($input)) {
        wt_json(['ok' => false, 'output' => "Bad request.\n"], 400);
    }
    $action = isset($input['action']) && is_string($input['action']) ? $input['action'] : 'exec';

    // ---- LOGIN ----
    if ($action === 'login') {
        if (!wt_hash_configured()) {
            wt_json([
                'ok'     => false,
                'output' => "Password is not configured. Set TERMINAL_PASSWORD_HASH in web_terminal.php.\n",
            ], 503);
        }
        $wait = wt_locked_for($wtIp);
        if ($wait > 0) {
            wt_json([
                'ok'     => false,
                'output' => "Too many failed attempts. Try again in {$wait} seconds.\n",
            ], 429);
        }
        $pwd = isset($input['password']) && is_string($input['password']) ? $input['password'] : '';
        if (wt_verify_password($pwd)) {
            wt_clear_failures($wtIp);
            session_regenerate_id(true);
            $_SESSION['auth'] = true;
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            $_SESSION['cwd']  = __DIR__;
            $_SESSION['last'] = time();
            wt_json([
                'ok'       => true,
                'output'   => "Authentication successful.\n",
                'csrf'     => $_SESSION['csrf'],
                'cwd'      => $_SESSION['cwd'],
                'executor' => wt_pick_executor(),
            ]);
        }
        wt_register_failure($wtIp);
        sleep(1);
        wt_json(['ok' => false, 'output' => "Authentication failed.\n"], 401);
    }

    // ---- LOGOUT ----
    if ($action === 'logout') {
        wt_require_auth();
        wt_session_destroy();
        wt_json(['ok' => true, 'output' => "Logged out.\n"]);
    }

    // ---- EXECUTE ----
    if ($action !== 'exec') {
        wt_json(['ok' => false, 'output' => "Unknown action.\n"], 400);
    }

    wt_require_auth();

    $command = isset($input['command']) && is_string($input['command']) ? trim($input['command']) : '';
    if ($command === '') {
        wt_json(['ok' => false, 'output' => "No command provided.\n"]);
    }
    if (strlen($command) > TERMINAL_MAX_COMMAND_LEN) {
        wt_json(['ok' => false, 'output' => "Command too long.\n"]);
    }
    if (wt_pick_executor() === null) {
        wt_json([
            'ok'     => false,
            'output' => "This host has disabled every PHP command-execution function "
                . "(" . implode(', ', wt_executors()) . ").\n",
        ]);
    }

    @set_time_limit(TERMINAL_COMMAND_TIMEOUT + 10);

    $cwd    = isset($_SESSION['cwd']) && is_string($_SESSION['cwd']) ? $_SESSION['cwd'] : __DIR__;
    $marker = '__WT_' . bin2hex(random_bytes(8)) . '__';
    $result = wt_run(wt_build_script($command, $cwd, $marker));

    if ($result === null) {
        wt_json(['ok' => false, 'output' => "Could not start the command on this host.\n"]);
    }

    list($raw, $rc, $newCwd) = wt_parse_output($result[0], $marker, $cwd);
    $_SESSION['cwd'] = $newCwd;

    $raw = rtrim($raw, "\r\n");
    wt_json([
        'ok'         => ($rc === null || $rc === 0),
        'output'     => $raw === '' ? '' : $raw . "\n",
        'statusCode' => $rc,
        'cwd'        => $newCwd,
    ]);
}

// ---------------- PAGE ----------------
$wtAuthed = wt_session_valid();
$wtBoot = [
    'authed'     => $wtAuthed,
    'csrf'       => $wtAuthed ? $_SESSION['csrf'] : '',
    'cwd'        => $wtAuthed ? ($_SESSION['cwd'] ?? __DIR__) : '',
    'https'      => $wtHttps,
    'configured' => wt_hash_configured(),
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
        body {
            margin: 0;
            padding: 0;
            background: #0e101a;
            color: #f5f5f5;
            font-family: 'Courier New', monospace;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .terminal-container {
            width: 90%;
            max-width: 960px;
            height: 80vh;
            background: #1a1c29;
            border-radius: 8px;
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            position: relative;
        }
        .terminal-header {
            padding: 10px 15px;
            background: #2e3047;
            color: #9da5b4;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 14px;
        }
        .terminal-header .title {
            font-weight: bold;
        }
        .terminal-header .right {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .logout-btn {
            display: none;
            background: transparent;
            color: #9da5b4;
            border: 1px solid #3d415c;
            border-radius: 4px;
            padding: 2px 8px;
            font-family: inherit;
            font-size: 12px;
            cursor: pointer;
        }
        .logout-btn:hover {
            color: #ff6c6c;
            border-color: #ff6c6c;
        }
        .terminal-output {
            flex: 1;
            padding: 10px;
            overflow-y: auto;
            background: #141622;
            color: #d3d7e0;
            font-size: 14px;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .terminal-input {
            display: flex;
            padding: 10px;
            background: #2e3047;
            border-top: 1px solid #3d415c;
        }
        .terminal-input .prompt {
            margin-right: 8px;
            color: #6a75a1;
            user-select: none;
            max-width: 45%;
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
            color: #e5e5e5;
            font-family: inherit;
            font-size: 14px;
        }
        /* Login overlay styles */
        .login-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-box {
            background: #1a1c29;
            border-radius: 6px;
            padding: 20px 30px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
            display: flex;
            flex-direction: column;
            gap: 10px;
            width: 320px;
            max-width: 80%;
        }
        .login-box h2 {
            margin: 0 0 10px 0;
            color: #f5f5f5;
            font-size: 20px;
            text-align: center;
        }
        .login-box input[type="password"] {
            padding: 8px;
            border-radius: 4px;
            border: none;
            outline: none;
            font-size: 14px;
        }
        .login-box button {
            padding: 8px;
            border-radius: 4px;
            border: none;
            background: #4a5fc1;
            color: #fff;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s ease;
        }
        .login-box button:hover {
            background: #3d51a3;
        }
        .login-box button:disabled {
            opacity: 0.6;
            cursor: default;
        }
        .login-error {
            color: #ff6c6c;
            font-size: 13px;
            display: none;
        }
        .terminal-footer {
            padding: 8px 12px;
            background: #2e3047;
            color: #9da5b4;
            font-size: 13px;
            text-align: right;
            border-top: 1px solid #3d415c;
            user-select: none;
        }
        .terminal-footer a {
            color: #8fb1ff;
            text-decoration: none;
            font-weight: 600;
        }
        .terminal-footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
<div class="terminal-container">
    <div class="terminal-header">
        <div class="title">Web Terminal</div>
        <div class="right">
            <div class="status" id="statusText">Not Authenticated</div>
            <button class="logout-btn" id="logoutBtn" type="button">Logout</button>
        </div>
    </div>
    <div id="terminalOutput" class="terminal-output"></div>
    <div class="terminal-input">
        <span class="prompt" id="promptEl">$</span>
        <input type="text" id="commandInput" placeholder="Type a command..." autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" disabled />
    </div>
    <!-- Login overlay layered on top of terminal until login succeeds -->
    <div class="login-overlay" id="loginOverlay">
        <div class="login-box">
            <h2>Login</h2>
            <input type="password" id="loginPassword" placeholder="Enter password" autocomplete="current-password" autofocus />
            <button id="loginButton" type="button">Login</button>
            <div class="login-error" id="loginError"></div>
        </div>
    </div>
    <footer class="terminal-footer">Built with ❤️ in Bangladesh by <a href="https://iamnaime.info.bd" target="_blank" rel="noopener noreferrer">Fattain Naime</a></footer>
</div>

<script>
    const BOOT = <?php echo json_encode($wtBoot, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;

    const outputEl = document.getElementById('terminalOutput');
    const cmdInput = document.getElementById('commandInput');
    const statusText = document.getElementById('statusText');
    const promptEl = document.getElementById('promptEl');
    const logoutBtn = document.getElementById('logoutBtn');

    // Login elements
    const loginOverlay = document.getElementById('loginOverlay');
    const loginButton  = document.getElementById('loginButton');
    const loginPassword = document.getElementById('loginPassword');
    const loginError   = document.getElementById('loginError');

    // The password is never kept in the browser. After login the server issues a
    // session cookie (HttpOnly) plus a CSRF token that is sent with every command.
    let csrf = BOOT.csrf || '';
    let cwd = BOOT.cwd || '';
    let authed = false;
    let busy = false;
    let history = [];
    let historyIndex = -1;

    function appendOutput(text) {
        outputEl.textContent += text;
        outputEl.scrollTop = outputEl.scrollHeight;
    }

    function promptText() {
        return (cwd || '~') + ' $';
    }

    function updatePrompt() {
        promptEl.textContent = promptText();
        promptEl.title = cwd;
    }

    function enterTerminal() {
        authed = true;
        loginOverlay.style.display = 'none';
        cmdInput.disabled = false;
        logoutBtn.style.display = 'inline-block';
        statusText.textContent = 'Authenticated';
        updatePrompt();
        cmdInput.focus();
    }

    function leaveTerminal(message) {
        authed = false;
        csrf = '';
        cwd = '';
        cmdInput.disabled = true;
        cmdInput.value = '';
        logoutBtn.style.display = 'none';
        statusText.textContent = 'Not Authenticated';
        loginOverlay.style.display = 'flex';
        loginPassword.value = '';
        loginPassword.focus();
        updatePrompt();
        if (message) appendOutput(message);
    }

    async function api(payload) {
        const headers = { 'Content-Type': 'application/json' };
        if (csrf) headers['X-CSRF-Token'] = csrf;
        const res = await fetch(window.location.href, {
            method: 'POST',
            headers: headers,
            credentials: 'same-origin',
            body: JSON.stringify(payload)
        });
        let data;
        try {
            data = await res.json();
        } catch (e) {
            data = { ok: false, output: 'Unexpected server response (HTTP ' + res.status + ').\n' };
        }
        data.httpStatus = res.status;
        return data;
    }

    function showLoginError(text) {
        loginError.textContent = text;
        loginError.style.display = 'block';
    }

    // Perform login by sending the password to the server for validation
    async function performLogin() {
        const pwd = loginPassword.value;
        if (!pwd || loginButton.disabled) return;
        loginButton.disabled = true;
        loginError.style.display = 'none';
        try {
            const data = await api({ action: 'login', password: pwd });
            if (data.ok) {
                csrf = data.csrf;
                cwd = data.cwd;
                loginPassword.value = '';
                if (data.executor) {
                    appendOutput('Using PHP function: ' + data.executor + '()\n\n');
                }
                enterTerminal();
            } else {
                showLoginError((data.output || 'Authentication failed.').trim());
                // Clear the wrong password for security
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
        try { await api({ action: 'logout' }); } catch (e) { /* ignore */ }
        leaveTerminal('Logged out.\n');
    }

    loginButton.addEventListener('click', performLogin);
    loginPassword.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            performLogin();
        }
    });
    logoutBtn.addEventListener('click', performLogout);

    // Execute commands via AJAX using the session cookie + CSRF token
    async function runCommand(command) {
        const cmd = command.trim();
        if (!cmd) return;
        if (cmd === 'clear') {
            outputEl.textContent = '';
            return;
        }
        if (cmd === 'logout' || cmd === 'exit') {
            performLogout();
            return;
        }
        appendOutput(promptText() + ' ' + command + '\n');
        busy = true;
        cmdInput.disabled = true;
        try {
            const data = await api({ action: 'exec', command: cmd });
            if (data.httpStatus === 401 && data.auth === false) {
                leaveTerminal(data.output || 'Session expired.\n');
                return;
            }
            appendOutput(data.output || '');
            if (data.cwd) {
                cwd = data.cwd;
                updatePrompt();
            }
            if (data.statusCode !== null && data.statusCode !== undefined && data.statusCode !== 0) {
                appendOutput('(exit code: ' + data.statusCode + ')\n');
            }
        } catch (e) {
            appendOutput('Error contacting server.\n');
        } finally {
            busy = false;
            if (authed) {
                cmdInput.disabled = false;
                cmdInput.focus();
            }
        }
    }

    cmdInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            if (busy) return;
            const cmd = cmdInput.value;
            if (cmd.trim() && history[history.length - 1] !== cmd) {
                history.push(cmd);
            }
            historyIndex = history.length;
            cmdInput.value = '';
            runCommand(cmd);
        } else if (e.key === 'l' && e.ctrlKey) {
            e.preventDefault();
            outputEl.textContent = '';
        } else if (e.key === 'ArrowUp') {
            if (historyIndex > 0) {
                historyIndex--;
                cmdInput.value = history[historyIndex] || '';
                setTimeout(() => cmdInput.setSelectionRange(cmdInput.value.length, cmdInput.value.length), 0);
            }
            e.preventDefault();
        } else if (e.key === 'ArrowDown') {
            if (historyIndex < history.length - 1) {
                historyIndex++;
                cmdInput.value = history[historyIndex] || '';
            } else {
                historyIndex = history.length;
                cmdInput.value = '';
            }
            e.preventDefault();
        }
    });

    // Focus the input on click, but never steal focus while the user is selecting output text
    document.addEventListener('click', () => {
        if (cmdInput.disabled) return;
        const sel = window.getSelection ? window.getSelection().toString() : '';
        if (!sel) {
            cmdInput.focus();
        }
    });

    // Initial greeting inside the terminal
    appendOutput('Web Terminal (type commands after login)\n');
    appendOutput('Tips: "clear" or Ctrl+L clears the screen, "exit" logs out.\n');
    if (!BOOT.https) {
        appendOutput('WARNING: this page is not served over HTTPS. Your password and commands can be intercepted.\n');
    }
    if (!BOOT.configured) {
        appendOutput('Setup required: set TERMINAL_PASSWORD_HASH in web_terminal.php (see README).\n');
    }
    appendOutput('\n');

    if (BOOT.authed) {
        enterTerminal();
    }
</script>
</body>
</html>
