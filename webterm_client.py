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
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

try:
    import readline  # noqa: F401  (enables arrow-key history in the REPL, if available)
except ImportError:
    pass

CONFIG_DIR = os.path.join(os.path.expanduser('~'), '.config', 'webterm')
POLL_INTERVAL = 0.7


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class WebTermError(Exception):
    pass


class WebTermClient:
    def __init__(self, url, insecure=False):
        self.url = url
        self.api_key = None
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

    def _request(self, payload, expect_json=True, timeout=120):
        body = json.dumps(payload).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['X-Api-Key'] = self.api_key
        elif self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        req = urllib.request.Request(self.url, data=body, headers=headers, method='POST')
        try:
            resp = self.opener.open(req, timeout=timeout)
            status = resp.getcode()
            raw = resp.read()
        except urllib.error.HTTPError as e:
            status = e.code
            raw = e.read()
        except urllib.error.URLError as e:
            raise WebTermError('Could not reach {}: {}'.format(self.url, e.reason))

        if not expect_json:
            return status, raw

        try:
            data = json.loads(raw.decode('utf-8', errors='replace'))
        except ValueError:
            raise WebTermError('Server returned a non-JSON response (HTTP {}).'.format(status))
        data['_status'] = status
        return data

    def post(self, action, **fields):
        payload = {'action': action}
        payload.update(fields)
        data = self._request(payload)
        if data.get('_status') == 401:
            raise AuthError(data.get('output', 'Authentication failed.').strip())
        return data

    # ---- auth ----

    def login_password(self, password):
        data = self._request({'action': 'login', 'password': password})
        if not data.get('ok'):
            raise WebTermError((data.get('output') or 'Login failed.').strip())
        self.csrf = data.get('csrf')
        self.cwd = data.get('cwd')
        return data

    def use_api_key(self, key):
        self.api_key = key
        data = self.post('whoami')
        if not data.get('ok'):
            raise WebTermError('API key rejected by server.')
        self.cwd = data.get('cwd')
        return data

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
            try:
                while True:
                    time.sleep(POLL_INTERVAL)
                    pdata = self.post('poll', job=self.current_job, offset=offset)
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
        data = self.post('upload', path=remote_path, data=b64)
        return data

    def download(self, remote_path, local_path):
        status, raw = self._request({'action': 'download', 'path': remote_path}, expect_json=False)
        if status != 200:
            try:
                err = json.loads(raw.decode('utf-8', errors='replace'))
                raise WebTermError(err.get('output', 'Download failed.').strip())
            except ValueError:
                raise WebTermError('Download failed (HTTP {}).'.format(status))
        with open(local_path, 'wb') as f:
            f.write(raw)
        return len(raw)


class AuthError(WebTermError):
    pass


def load_profile(name):
    path = os.path.join(CONFIG_DIR, name + '.json')
    if os.path.isfile(path):
        with open(path) as f:
            return json.load(f)
    return None


def save_profile(name, url, api_key):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    path = os.path.join(CONFIG_DIR, name + '.json')
    with open(path, 'w') as f:
        json.dump({'url': url, 'api_key': api_key}, f)
    os.chmod(path, 0o600)


def connect(args):
    url = args.url
    api_key = args.api_key or os.environ.get('WEBTERM_API_KEY')
    profile = None
    if not url:
        profile = load_profile(args.profile)
        if not profile:
            eprint('No URL given and no saved profile "{}" found.'.format(args.profile))
            sys.exit(2)
        url = profile['url']
        api_key = api_key or profile.get('api_key')

    client = WebTermClient(url, insecure=args.insecure)

    if api_key:
        try:
            client.use_api_key(api_key)
        except WebTermError as e:
            eprint('API key login failed: {}'.format(e))
            sys.exit(1)
    else:
        password = args.password or getpass.getpass('Password for {}: '.format(url))
        try:
            client.login_password(password)
        except WebTermError as e:
            eprint('Login failed: {}'.format(e))
            sys.exit(1)

    if args.save:
        save_profile(args.profile, url, api_key)
        eprint('Saved profile "{}" (api key only, never the password) to {}'.format(args.profile, CONFIG_DIR))

    return client


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
            eprint(__doc__.split('Interactive session built-ins')[1])
            continue
        if cmd == '!clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            continue
        if cmd == '!jobs':
            for j in client.jobs():
                state = 'running' if j['running'] else 'exit {}'.format(j['exit'])
                print('{}  {:<10} {}'.format(j['id'][:12], state, j['command']))
            continue
        if cmd.startswith('!kill '):
            job_id = cmd.split(None, 1)[1].strip()
            try:
                client.kill(job_id)
                print('Kill signal sent.')
            except WebTermError as e:
                eprint(str(e))
            continue
        if cmd == '!history':
            for h in client.history():
                print(h)
            continue
        if cmd.startswith('!upload '):
            parts = cmd.split()
            if len(parts) < 3:
                eprint('Usage: !upload <local> <remote>')
                continue
            try:
                client.upload(parts[1], parts[2])
                print('Uploaded {} -> {}'.format(parts[1], parts[2]))
            except (WebTermError, OSError) as e:
                eprint('Upload failed: {}'.format(e))
            continue
        if cmd.startswith('!download '):
            parts = cmd.split()
            if len(parts) < 3:
                eprint('Usage: !download <remote> <local>')
                continue
            try:
                n = client.download(parts[1], parts[2])
                print('Downloaded {} bytes -> {}'.format(n, parts[2]))
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
    except WebTermError as e:
        eprint(str(e))
        sys.exit(1)


if __name__ == '__main__':
    # Let Ctrl+C during network waits raise KeyboardInterrupt promptly.
    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
    except (ValueError, AttributeError):
        pass
    main()
