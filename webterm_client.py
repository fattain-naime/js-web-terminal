#!/usr/bin/env python3
"""
webterm_client.py - command-line client for Web Terminal Pro (web_terminal.php).

Lets you use a PHP-only "web terminal" exactly like a real remote shell, from
your own terminal, with no extra dependencies (Python 3 standard library
only).

Quick start
-----------
  # One-shot command (like `ssh host command`), exits with the remote exit code
  python3 webterm_client.py https://example.com/web_terminal.php -c "git pull"

  # Interactive session (REPL), asks for the password if no API key is given
  python3 webterm_client.py https://example.com/web_terminal.php

  # Script-friendly: use an API key instead of a password (see web_terminal.php
  # setup instructions for how to generate one)
  export WEBTERM_API_KEY=...
  python3 webterm_client.py https://example.com/web_terminal.php -c "uptime"

  # Upload / download without entering the REPL
  python3 webterm_client.py URL --upload ./build.zip build.zip
  python3 webterm_client.py URL --download remote.log ./remote.log

Interactive session built-ins (not sent to the remote shell):
  !upload <local> <remote>   !download <remote> <local>
  !jobs                      !kill <job-id>
  !history                   !clear
  !help                      exit / logout

Long-running remote commands are handled automatically: the server turns them
into a background job and this client streams the output as it polls, exactly
like the browser UI does. Press Ctrl+C to send a kill signal to the job that
is currently running.
"""

import argparse
import base64
import getpass
import json
import os
import re
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from http.client import responses as http_reasons
from http.cookiejar import CookieJar

try:
    import readline  # noqa: F401  (enables arrow-key history in the REPL, if available)
except ImportError:
    pass

CONFIG_DIR = os.path.join(os.path.expanduser('~'), '.config', 'webterm')
POLL_INTERVAL = 0.7
POLL_TIMEOUT = 30
POLL_MAX_RETRIES = 5
POLL_RETRY_DELAY = 2.0
REQUEST_TIMEOUT = 120

# Some hosts (WAFs, bot filters, mod_security rules) reject requests whose
# User-Agent is the default "Python-urllib/x.y" with a 403 before the request
# ever reaches PHP, so identify ourselves honestly instead.
DEFAULT_USER_AGENT = 'webterm-client/1.0 (+https://github.com/fattain-naime/js-web-terminal)'
USER_AGENT = os.environ.get('WEBTERM_USER_AGENT') or DEFAULT_USER_AGENT

PROFILE_NAME_RE = re.compile(r'\A[A-Za-z0-9._-]+\Z')


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class WebTermError(Exception):
    pass


class AuthError(WebTermError):
    pass


def body_snippet(raw, limit=240):
    """A short, readable excerpt of a non-JSON response body, for error messages."""
    text = raw.decode('utf-8', errors='replace')
    text = re.sub(r'<[^>]*>', ' ', text)
    text = ' '.join(text.split())
    if len(text) > limit:
        text = text[:limit] + '...'
    return text


def describe_bad_response(status, raw, url):
    """Explain a response that isn't the JSON API, instead of a bare status code."""
    reason = http_reasons.get(status, '')
    msg = 'Server returned HTTP {}{}.'.format(status, ' ' + reason if reason else '')
    snippet = body_snippet(raw)
    if snippet:
        msg += ' Body: ' + snippet
    if status == 401:
        msg += ' The server rejected the credentials.'
    elif status == 403:
        msg += (' The request was blocked before it reached the API: check TERMINAL_ALLOWED_IPS, '
                'any web-server/WAF/CDN rules in front of the script, and that ' + url +
                ' is not behind a login redirect.')
    elif status == 404:
        msg += ' Check that the URL points at web_terminal.php.'
    elif status == 429:
        msg += ' The server is rate-limiting this IP - too many failed logins; wait and retry.'
    elif status >= 500:
        msg += ' The server failed while running the PHP script - check its error log.'
    elif status < 400:
        msg += (' The URL may not be web_terminal.php, or the server redirected the request '
                '(a hosting login page does exactly that).')
    return msg


class WebTermClient:
    def __init__(self, url, insecure=False):
        if not re.match(r'\Ahttps?://', url, re.IGNORECASE):
            raise WebTermError('URL must start with http:// or https:// (got {!r}).'.format(url))
        self.url = url
        self.api_key = None
        # Some hosts/WAFs strip or reject custom request headers, so the server
        # also accepts the key in the JSON body - see use_api_key().
        self.api_key_in_body = False
        self.csrf = None
        self.cwd = None
        self.current_job = None
        self.cookiejar = CookieJar()
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPCookieProcessor(self.cookiejar),
                    urllib.request.HTTPSHandler(context=ctx)]
        self.opener = urllib.request.build_opener(*handlers)

    # ---- low level ----

    def _request(self, payload, expect_json=True, timeout=REQUEST_TIMEOUT):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': USER_AGENT,
        }
        if self.api_key and self.api_key_in_body:
            payload = dict(payload, api_key=self.api_key)
        elif self.api_key:
            headers['X-Api-Key'] = self.api_key
        elif self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(self.url, data=body, headers=headers, method='POST')
        try:
            resp = self.opener.open(req, timeout=timeout)
            status = resp.getcode()
            raw = resp.read()
            resp.close()
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                raw = e.read()
            finally:
                e.close()
        except urllib.error.URLError as e:
            raise WebTermError('Could not reach {}: {}'.format(self.url, e.reason))
        except OSError as e:
            # Timeouts and resets while reading the body are not wrapped in URLError.
            raise WebTermError('Request to {} failed: {}'.format(self.url, e))

        if not expect_json:
            return status, raw

        try:
            data = json.loads(raw.decode('utf-8', errors='replace'))
        except ValueError:
            raise WebTermError(describe_bad_response(status, raw, self.url))
        if not isinstance(data, dict):
            raise WebTermError('Server returned an unexpected JSON value (not an object).')
        data['_status'] = status
        return data

    def post(self, action, timeout=REQUEST_TIMEOUT, **fields):
        payload = {'action': action}
        payload.update(fields)
        data = self._request(payload, timeout=timeout)
        status = data.get('_status', 200)
        if status == 401:
            raise AuthError(str(data.get('output') or data.get('error') or 'Authentication failed.').strip())
        if status >= 400:
            # An HTTP error status always means the action did not happen - report
            # the server's own message instead of pretending the call succeeded.
            raise WebTermError(str(data.get('output') or data.get('error')
                                   or 'Server returned HTTP {}.'.format(status)).strip())
        return data

    # ---- auth ----

    def login_password(self, password):
        data = self._request({'action': 'login', 'password': password})
        if not data.get('ok'):
            raise AuthError(str(data.get('output') or 'Login failed.').strip())
        self.csrf = data.get('csrf')
        self.cwd = data.get('cwd')
        return data

    def use_api_key(self, key):
        """Authenticate with an API key, retrying once with the key in the body.

        Some hosts (or a WAF in front of them) strip or reject the X-Api-Key header.
        The server reads the key from the JSON body too, so one retry with the
        header dropped covers that without the user needing a different client.
        """
        self.api_key = key
        for in_body in (False, True):
            self.api_key_in_body = in_body
            data = self._request({'action': 'whoami'})
            if data.get('ok'):
                self.cwd = data.get('cwd')
                return data
            # Retry in the body only when the server never saw a key at all -
            # that means the header was stripped, not that the key is wrong, so
            # this does not burn another attempt from the server's rate limit.
            if data.get('noCredentials') and not in_body:
                continue
            if data.get('_status') == 401:
                raise AuthError(str(data.get('output') or data.get('error')
                                    or 'API key rejected by server.').strip())
            if data.get('_status', 200) >= 400:
                raise WebTermError(str(data.get('output') or data.get('error')
                                       or 'Server returned HTTP {}.'.format(data['_status'])).strip())
            raise AuthError(str(data.get('output') or data.get('error')
                                            or 'API key rejected by server.').strip())

    def logout(self):
        try:
            self.post('logout')
        except Exception:
            pass

    # ---- exec / poll / kill ----

    def exec_stream(self, command, on_output):
        """Run a command, streaming output to on_output(text). Returns exit code (int or None)."""
        data = self.post('exec', command=command)
        on_output(data.get('output') or '')
        if data.get('cwd'):
            self.cwd = data['cwd']
        if data.get('state') == 'running' and data.get('job'):
            self.current_job = data['job']
            offset = data.get('offset', 0)
            transient = 0
            try:
                while True:
                    time.sleep(POLL_INTERVAL)
                    try:
                        pdata = self.post('poll', timeout=POLL_TIMEOUT,
                                          job=self.current_job, offset=offset)
                    except AuthError:
                        raise
                    except WebTermError as e:
                        # A transient 429/5xx must not orphan the job: the server is
                        # still running it and we are the only handle on it. Retry a
                        # few times before giving up, then report the job id so the
                        # user can still kill it by hand.
                        transient += 1
                        if transient > POLL_MAX_RETRIES:
                            eprint('\n[giving up polling job {}: {}]'.format(self.current_job, e))
                            raise
                        time.sleep(POLL_RETRY_DELAY)
                        continue
                    transient = 0
                    on_output(pdata.get('output') or '')
                    offset = pdata.get('offset', offset)
                    if pdata.get('state') == 'done':
                        self.current_job = None
                        if pdata.get('cwd'):
                            self.cwd = pdata['cwd']
                        return pdata.get('exitCode')
            except KeyboardInterrupt:
                eprint('\n[sending kill signal...]')
                try:
                    self.post('kill', job=self.current_job)
                except Exception:
                    pass
                self.current_job = None
                raise
        return data.get('exitCode')

    def kill(self, job_id):
        return self.post('kill', job=job_id)

    def jobs(self):
        return self.post('jobs').get('jobs', [])

    def history(self):
        return self.post('history').get('history', [])

    # ---- files ----

    def upload(self, local_path, remote_path):
        with open(local_path, 'rb') as f:
            raw = f.read()
        b64 = base64.b64encode(raw).decode('ascii')
        return self.post('upload', path=remote_path, data=b64)

    def download(self, remote_path, local_path):
        status, raw = self._request({'action': 'download', 'path': remote_path}, expect_json=False)
        if status != 200:
            try:
                err = json.loads(raw.decode('utf-8', errors='replace'))
            except ValueError:
                raise WebTermError(describe_bad_response(status, raw, self.url))
            if isinstance(err, dict):
                raise WebTermError(str(err.get('output') or err.get('error') or 'Download failed.').strip())
            raise WebTermError('Download failed (HTTP {}).'.format(status))
        with open(local_path, 'wb') as f:
            f.write(raw)
        return len(raw)


def profile_path(name):
    if not PROFILE_NAME_RE.match(name or ''):
        raise WebTermError('Invalid profile name {!r}.'.format(name))
    return os.path.join(CONFIG_DIR, name + '.json')


def load_profile(name):
    path = profile_path(name)
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def save_profile(name, url, api_key):
    path = profile_path(name)
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'url': url, 'api_key': api_key}, f)
    os.chmod(path, 0o600)


def connect(args):
    try:
        # Validate the name up front so a bad --profile fails cleanly even when a
        # URL was given on the command line and the profile is never read.
        profile_path(args.profile)
    except WebTermError as e:
        eprint(str(e))
        sys.exit(2)

    url = args.url
    api_key = args.api_key or os.environ.get('WEBTERM_API_KEY')
    if not url:
        profile = load_profile(args.profile)
        if not profile:
            eprint('No URL given and no saved profile "{}" found.'.format(args.profile))
            sys.exit(2)
        url = profile.get('url') or ''
        api_key = api_key or profile.get('api_key')
    if not url:
        eprint('Saved profile "{}" has no URL.'.format(args.profile))
        sys.exit(2)

    try:
        client = WebTermClient(url, insecure=args.insecure)
    except WebTermError as e:
        eprint(str(e))
        sys.exit(2)

    if api_key:
        try:
            client.use_api_key(api_key)
        except AuthError as e:
            # Keep the server's own wording - it distinguishes "no key configured
            # on the server" from "this key is wrong" - and add the rate-limit hint.
            eprint('API key login failed: {}'.format(e))
            eprint('Check TERMINAL_API_KEY_HASH on the server, and whether this IP is '
                   'locked out after too many failed attempts.')
            sys.exit(1)
        except WebTermError as e:
            eprint('API key login failed: {}'.format(e))
            sys.exit(1)
    else:
        try:
            password = args.password or getpass.getpass('Password for {}: '.format(url))
        except (EOFError, KeyboardInterrupt):
            eprint('\nNo password given.')
            sys.exit(2)
        try:
            client.login_password(password)
        except WebTermError as e:
            eprint('Login failed: {}'.format(e))
            sys.exit(1)

    if args.save:
        if api_key:
            try:
                save_profile(args.profile, url, api_key)
            except (WebTermError, OSError) as e:
                eprint('Could not save profile: {}'.format(e))
                sys.exit(1)
            eprint('Saved profile "{}" (api key only, never the password) to {}'.format(
                args.profile, CONFIG_DIR))
        else:
            eprint('Nothing to save: profiles store the URL and API key only. Re-run with '
                   '--api-key, or set WEBTERM_API_KEY, to save a profile.')

    return client


REPL_HELP = """
  !upload <local> <remote>     upload a local file to the server
  !download <remote> <local>   download a remote file
  !jobs                        list background jobs
  !kill <job-id>                kill a background job
  !history                     show shared command history
  !clear                       clear the local screen
  !help                        show this help
  exit / logout / quit         log out and quit

Paths containing spaces can be quoted: !download "my file.txt" ./out.txt
Everything else is sent to the server as a real shell command.
"""


def print_chunk(text):
    if text:
        sys.stdout.write(text)
        sys.stdout.flush()


def run_one_shot(client, command):
    try:
        code = client.exec_stream(command, print_chunk)
    except KeyboardInterrupt:
        sys.exit(130)
    sys.exit(code if isinstance(code, int) else 0)


def split_args(text):
    """Split a built-in's arguments, honouring quotes so paths may contain spaces.

    Deliberately not shlex: its POSIX mode reads a backslash as an escape and so
    strips the separators out of a Windows path.
    """
    return [quoted or bare for quoted, bare in re.findall(r'"([^"]*)"|(\S+)', text)]


def repl(client):
    eprint('Connected to {}'.format(client.url))
    eprint('Type a command, or !help for client-side commands. exit / logout to quit.\n')
    while True:
        prompt = '{} $ '.format(client.cwd or '~')
        try:
            line = input(prompt)
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in ('exit', 'logout', 'quit'):
            break
        if cmd == '!help':
            eprint(REPL_HELP)
            continue
        if cmd == '!clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            continue
        if cmd == '!jobs':
            try:
                jobs = client.jobs()
            except WebTermError as e:
                eprint(str(e))
                continue
            for j in jobs:
                state = 'running' if j.get('running') else 'exit {}'.format(j.get('exit'))
                print('{}  {:<10} {}'.format(str(j.get('id', ''))[:12], state, j.get('command', '')))
            continue
        if cmd.startswith('!kill '):
            parts = split_args(cmd[len('!kill '):])
            if not parts:
                eprint('Usage: !kill <job-id>')
                continue
            try:
                client.kill(parts[0])
                print('Kill signal sent.')
            except WebTermError as e:
                eprint(str(e))
            continue
        if cmd == '!history':
            try:
                entries = client.history()
            except WebTermError as e:
                eprint(str(e))
                continue
            for h in entries:
                print(h)
            continue
        if cmd.startswith('!upload '):
            parts = split_args(cmd[len('!upload '):])
            if len(parts) != 2:
                eprint('Usage: !upload <local> <remote>')
                continue
            try:
                client.upload(parts[0], parts[1])
                print('Uploaded {} -> {}'.format(parts[0], parts[1]))
            except (WebTermError, OSError) as e:
                eprint('Upload failed: {}'.format(e))
            continue
        if cmd.startswith('!download '):
            parts = split_args(cmd[len('!download '):])
            if len(parts) != 2:
                eprint('Usage: !download <remote> <local>')
                continue
            try:
                n = client.download(parts[0], parts[1])
                print('Downloaded {} bytes -> {}'.format(n, parts[1]))
            except (WebTermError, OSError) as e:
                eprint('Download failed: {}'.format(e))
            continue

        try:
            code = client.exec_stream(cmd, print_chunk)
        except KeyboardInterrupt:
            continue
        except AuthError as e:
            eprint('\n[session expired: {}]'.format(e))
            break
        except WebTermError as e:
            eprint(str(e))
            continue
        if code not in (0, None):
            eprint('(exit code: {})'.format(code))

    client.logout()


def main():
    parser = argparse.ArgumentParser(description='CLI client for Web Terminal Pro.')
    parser.add_argument('url', nargs='?', help='URL of web_terminal.php')
    parser.add_argument('-c', '--command', help='Run one command and exit with its exit code')
    parser.add_argument('--password', help='Password (prompted securely if omitted and no API key is set)')
    parser.add_argument('--api-key', help='API key (or set WEBTERM_API_KEY)')
    parser.add_argument('--insecure', action='store_true', help='Do not verify TLS certificates')
    parser.add_argument('--profile', default='default', help='Saved profile name (default: "default")')
    parser.add_argument('--save', action='store_true', help='Save URL + API key (never the password) to ~/.config/webterm/')
    parser.add_argument('--upload', nargs=2, metavar=('LOCAL', 'REMOTE'), help='Upload a file and exit')
    parser.add_argument('--download', nargs=2, metavar=('REMOTE', 'LOCAL'), help='Download a file and exit')
    args = parser.parse_args()

    client = connect(args)

    try:
        if args.upload:
            client.upload(args.upload[0], args.upload[1])
            print('Uploaded {} -> {}'.format(*args.upload))
        elif args.download:
            n = client.download(args.download[0], args.download[1])
            print('Downloaded {} bytes -> {}'.format(n, args.download[1]))
        elif args.command:
            run_one_shot(client, args.command)
        else:
            repl(client)
    except AuthError as e:
        eprint(str(e))
        sys.exit(1)
    except WebTermError as e:
        eprint(str(e))
        sys.exit(1)
    except OSError as e:
        eprint('Local file error: {}'.format(e))
        sys.exit(1)
    except KeyboardInterrupt:
        eprint('\nInterrupted.')
        sys.exit(130)


if __name__ == '__main__':
    # Let Ctrl+C during network waits raise KeyboardInterrupt promptly.
    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
    except (ValueError, AttributeError):
        pass
    main()
