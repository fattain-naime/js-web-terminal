# Web Terminal

This project provides a lightweight, browser‑based terminal written in PHP.  It allows you to execute arbitrary commands on the host machine from any modern web browser after successful authentication.  The interface is designed to look and feel like a real terminal, with command history, a dark theme and responsive layout.

## Features

- **Login before use** – Users must authenticate with a password before accessing the terminal.  The password is never stored in plain text; instead the MD5 hash of the password is compared on the server.
- **Unrestricted command execution** – Once authenticated, any command string entered into the terminal will be executed on the server.  There is no allow‑list, so you have full control of the host environment.
- **Modern UI/UX** – The interface uses a sleek, dark colour scheme with a clear header showing authentication status, a large scrollable output area and a neat input prompt.  A semi‑transparent overlay appears on load to prompt the user for their password.
- **Command history navigation** – Use the up and down arrow keys to cycle through your previous commands.
- **Self‑contained** – The entire application is contained in a single PHP file (plus this README and a screenshot).  No external libraries or frameworks are required.

## Getting Started

### Prerequisites

To run the web terminal you need:

- A web server capable of running PHP (PHP 7.0+ is recommended).  You can also use PHP’s built‑in server for local development.
- Access to the filesystem where you can deploy the script.

### Installation

1. Clone or download this repository to your web server’s document root:

   ```bash
   git clone https://github.com/fattain-naime/js-web-terminal.git
   cd js-web-terminal
   ```

2. **Set your password**.  Open `web_terminal.php` and locate the line defining `TERMINAL_PASSWORD_HASH`.  Replace the existing hash with the MD5 hash of your desired password:

   ```php
   // MD5 hash of the password "123". Replace with md5('your-password')
   const TERMINAL_PASSWORD_HASH = '202cb962ac59075b964b07152d234b70';
   ```

   For example, to set the password to `supersecret`, compute `md5('supersecret')` (result: `8d3e3cdd0a75c1943d7e313fa3ca5f0d`) and paste that value into the constant.

3. (Optional) Adjust styling.  The terminal’s appearance is defined inline in the `<style>` tag.  Feel free to tweak colours, fonts or layout to suit your preference.

4. Deploy the script.  You can simply drop `web_terminal.php` into your web server’s document root.  If you’re using the built‑in PHP server for testing, run:

   ```bash
   php -S 127.0.0.1:8000 -t .
   ```

   Then navigate to `http://127.0.0.1:8000/web_terminal.php` in your browser.

## Usage

1. **Open the terminal** in your browser by navigating to the script.  You’ll see a login overlay prompting for a password.
2. **Enter your password** and click **Login**.  If the hash matches the stored hash, the overlay disappears and you can begin issuing commands.
3. **Execute commands** by typing them into the prompt and pressing `Enter`.  The output will appear immediately above the input line.
4. **Navigate history** using the up/down arrow keys to recall previously entered commands.

### Example

After logging in, try commands such as:

```sh
pwd            # Show the current working directory
ls -la         # List files in long format
php -v         # Display the PHP version running on the server
```

## Configuration

### Changing the working directory

If you want the terminal to operate in a specific directory, you can uncomment and modify the `chdir()` call in `web_terminal.php`:

```php
// chdir('/path/to/your/project');
```

### Customising the UI

All styling is embedded in the HTML file.  To customise:

- Edit colours and fonts in the `<style>` block to match your branding.
- Change the prompt text (`web@cpanel:~$`) in the HTML to reflect your environment.
- Modify the header status message via the `statusText` element in the JavaScript.

## Security Considerations

This project intentionally removes command restrictions to provide maximum flexibility.  As a result, **it will execute any command** the authenticated user supplies.  Keep in mind:

- **Never expose this terminal to the public internet**.  Restrict access (e.g. via IP filtering or HTTP basic auth) and use strong, unique passwords.
- **Run in a sandboxed or isolated environment** if possible.  Misuse of this tool could lead to data loss or server compromise.
- **Audit your commands** – there is no undo for destructive operations.

If you need a more constrained environment, consider reintroducing an allow‑list of safe commands as shown in earlier versions of this script.

## Contributing

Pull requests are welcome!  If you have ideas for improvements - such as additional authentication mechanisms, command logging, or UI enhancements - feel free to open an issue or submit a PR.

## License

This project is licensed under the GPL V2.0 License.  See the `LICENSE` file for details.
