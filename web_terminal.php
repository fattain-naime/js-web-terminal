<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

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
 * Change const password with yours.
 * TERMINAL_PASSWORD_HASH to the MD5 of your own password.
 */

// MD5 hash of the password "123". Replace with md5('your‑password')
const TERMINAL_PASSWORD_HASH = '202cb962ac59075b964b07152d234b70';

// ================== BACKEND (AJAX HANDLER) ==================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    $input = json_decode(file_get_contents('php://input'), true);
    $password = $input['password'] ?? '';
    $command  = isset($input['command']) ? trim($input['command']) : '';
    $action   = $input['action'] ?? '';

    // ---- LOGIN HANDLER ----
    // The client will hit this endpoint with {action: 'login', password: '<pwd>'}
    // to validate credentials before enabling the terminal. We do not execute
    // any commands for the login action. Instead we just return ok/not ok.
    if ($action === 'login') {
        if (md5($password) === TERMINAL_PASSWORD_HASH) {
            echo json_encode([
                'ok'     => true,
                'output' => "Authentication successful.\n",
            ]);
        } else {
            echo json_encode([
                'ok'     => false,
                'output' => "Authentication failed.\n",
            ]);
        }
        exit;
    }

    // ---- COMMAND HANDLER ----
    // Reject any request that does not provide the correct password.
    if (md5($password) !== TERMINAL_PASSWORD_HASH) {
        echo json_encode([
            'ok'     => false,
            'output' => "Authentication failed.\n",
        ]);
        exit;
    }

    // Command is required for execution
    if ($command === '') {
        echo json_encode([
            'ok'     => false,
            'output' => "No command provided.\n",
        ]);
        exit;
    }

    // Run the command without any allow‑list restrictions. This terminal
    // intentionally exposes the underlying system to arbitrary commands,
    // so be cautious deploying it in production. Output and status code
    // are returned to the client.
    $output    = [];
    $returnVar = 0;
    exec($command . ' 2>&1', $output, $returnVar);

    echo json_encode([
        'ok'        => $returnVar === 0,
        'output'    => implode("\n", $output) . "\n",
        'statusCode' => $returnVar,
    ]);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
            margin-right: 5px;
            color: #6a75a1;
            user-select: none;
        }
        .terminal-input input {
            flex: 1;
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
        <div class="status" id="statusText">Not Authenticated</div>
    </div>
    <div id="terminalOutput" class="terminal-output"></div>
    <div class="terminal-input">
        <span class="prompt">web@cpanel:~$</span>
        <input type="text" id="commandInput" placeholder="Type a command..." disabled />
    </div>
    <!-- Login overlay layered on top of terminal until login succeeds -->
    <div class="login-overlay" id="loginOverlay">
        <div class="login-box">
            <h2>Login</h2>
            <input type="password" id="loginPassword" placeholder="Enter password" autofocus />
            <button id="loginButton">Login</button>
            <div class="login-error" id="loginError">Invalid password, please try again.</div>
        </div>
    </div>
    <footer class="terminal-footer">Built with ❤️ in Bangladesh by <a href="https://iamnaime.info.bd" target="_blank" rel="noopener noreferrer">Fattain Naime</a></footer>
</div>

<script>
    const outputEl = document.getElementById('terminalOutput');
    const cmdInput = document.getElementById('commandInput');
    const statusText = document.getElementById('statusText');

    // Login elements
    const loginOverlay = document.getElementById('loginOverlay');
    const loginButton  = document.getElementById('loginButton');
    const loginPassword = document.getElementById('loginPassword');
    const loginError   = document.getElementById('loginError');

    // Cache the password after successful login so we don't store it globally
    let passwordCache = '';
    let history = [];
    let historyIndex = -1;

    function appendOutput(text) {
        outputEl.textContent += text;
        outputEl.scrollTop = outputEl.scrollHeight;
    }

    // Perform login by sending the password to the server for validation
    async function performLogin() {
        const pwd = loginPassword.value;
        if (!pwd) return;
        try {
            const res = await fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: pwd, action: 'login' })
            });
            const data = await res.json();
            if (data.ok) {
                passwordCache = pwd;
                loginOverlay.style.display = 'none';
                cmdInput.disabled = false;
                cmdInput.focus();
                statusText.textContent = 'Authenticated';
            } else {
                loginError.style.display = 'block';
                // Clear the wrong password for security
                loginPassword.value = '';
            }
        } catch (e) {
            loginError.textContent = 'Error contacting server.';
            loginError.style.display = 'block';
        }
    }

    loginButton.addEventListener('click', performLogin);
    loginPassword.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            performLogin();
        }
    });

    // Execute commands via AJAX. Use cached password for authentication
    async function runCommand(command) {
        if (!command.trim()) return;
        appendOutput("web@cpanel:~$ " + command + "\n");
        try {
            const res = await fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ command, password: passwordCache })
            });
            const data = await res.json();
            appendOutput(data.output || '');
            if (!data.ok) {
                appendOutput("(exit code: " + (data.statusCode ?? 'error') + ")\n");
            }
        } catch (e) {
            appendOutput("Error contacting server.\n");
        }
    }

    cmdInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const cmd = cmdInput.value;
            history.push(cmd);
            historyIndex = history.length;
            cmdInput.value = '';
            runCommand(cmd);
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

    // Allow focusing the input by clicking anywhere in the document after login
    document.addEventListener('click', () => {
        if (!cmdInput.disabled) {
            cmdInput.focus();
        }
    });

    // Initial greeting inside the terminal
    appendOutput("Web Terminal (type commands after login)\n\n");
</script>
</body>
</html>