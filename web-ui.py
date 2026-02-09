#!/usr/bin/env python3
"""Simple web UI for WireGuard client management.

This server is intentionally minimal and uses only Python standard library.
Run as root so it can execute the underlying shell scripts.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import subprocess
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CLIENT_SCRIPT = ROOT / "generate-wireguard-client.sh"
WG_IFACE = os.environ.get("WG_IFACE", "wg0")
WG_CONF = Path("/etc/wireguard") / f"{WG_IFACE}.conf"
CLIENTS_DIR = Path("/etc/wireguard/clients")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CLIENT_CONF_PATH_RE = re.compile(r"Client config:\s*(\S+)")
PEER_BLOCK_RE = re.compile(r"(?ms)^\[Peer\]\n.*?(?=^\[Peer\]\n|\Z)")
PUBLIC_KEY_LINE_RE = re.compile(r"(?m)^PublicKey\s*=\s*(\S+)\s*$")

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
CIDR_RE = re.compile(r"^[0-9a-fA-F:./]{3,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
DNS_RE = re.compile(r"^[0-9a-fA-F:.]{3,64}$")

STATE = {
    "last_action": "None",
    "last_status": "",
    "last_output": "",
    "last_qr_svg": "",
}


def _run_script(cmd: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "Operation timed out after 10 minutes."
    except OSError as exc:
        return False, f"Failed to execute command: {exc}"

    output = (completed.stdout or "") + ("\n" if completed.stdout and completed.stderr else "") + (completed.stderr or "")
    if completed.returncode == 0:
        return True, output.strip() or "Completed successfully."

    return False, f"Exit code {completed.returncode}\n\n{output.strip()}"


def _clean_output(output: str) -> str:
    cleaned = ANSI_ESCAPE_RE.sub("", output)
    # The script prints an ANSI terminal QR block between these markers.
    if "Scan QR code on mobile client:" in cleaned and "Raw config:" in cleaned:
        before, rest = cleaned.split("Scan QR code on mobile client:", 1)
        _, after = rest.split("Raw config:", 1)
        cleaned = before + "Scan QR code on mobile client: (rendered above)\n\nRaw config:" + after
    return cleaned.strip()


def _extract_client_conf_path(output: str) -> Path | None:
    match = CLIENT_CONF_PATH_RE.search(output)
    if not match:
        return None
    path = Path(match.group(1)).resolve()
    if not path.exists():
        return None
    return path


def _generate_qr_svg_from_config(config_text: str) -> str:
    try:
        completed = subprocess.run(
            ["qrencode", "-t", "svg", "-o", "-"],
            input=config_text,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""

    if completed.returncode != 0 or not completed.stdout.strip():
        return ""
    return completed.stdout


def _remove_peer_block_from_server_config(public_key: str, client_name: str) -> tuple[bool, str]:
    try:
        config_text = WG_CONF.read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"Failed reading server config {WG_CONF}: {exc}"

    removed_blocks = 0
    chunks: list[str] = []
    cursor = 0

    for match in PEER_BLOCK_RE.finditer(config_text):
        start, end = match.span()
        block = match.group(0)
        key_match = PUBLIC_KEY_LINE_RE.search(block)
        block_key = key_match.group(1).strip() if key_match else ""

        if block_key == public_key:
            keep_end = start
            if keep_end > 0 and config_text[keep_end - 1] == "\n":
                keep_end -= 1
            chunks.append(config_text[cursor:keep_end])
            cursor = end
            removed_blocks += 1

    if removed_blocks == 0:
        return True, f"No matching peer block found in {WG_CONF} for '{client_name}' (already removed or saved differently)."

    chunks.append(config_text[cursor:])
    updated = "".join(chunks)

    try:
        WG_CONF.write_text(updated, encoding="utf-8")
    except OSError as exc:
        return False, f"Failed writing server config {WG_CONF}: {exc}"

    return True, f"Removed {removed_blocks} peer block(s) for '{client_name}' from {WG_CONF}."


def _remove_client(client_name: str) -> tuple[bool, str]:
    messages: list[str] = []
    had_error = False

    pub_key_path = CLIENTS_DIR / f"{client_name}.public.key"
    private_key_path = CLIENTS_DIR / f"{client_name}.private.key"
    conf_path = CLIENTS_DIR / f"{client_name}.conf"
    public_key = ""

    if pub_key_path.exists():
        try:
            public_key = pub_key_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            had_error = True
            messages.append(f"Failed reading {pub_key_path}: {exc}")

    if public_key:
        removed_runtime, runtime_output = _run_script(["wg", "set", WG_IFACE, "peer", public_key, "remove"])
        if removed_runtime:
            messages.append(f"Removed peer from live interface '{WG_IFACE}'.")
        else:
            had_error = True
            messages.append(f"Could not remove peer from live interface '{WG_IFACE}'.")
            messages.append(runtime_output)

    if public_key:
        removed_conf, conf_message = _remove_peer_block_from_server_config(public_key, client_name)
        if not removed_conf:
            had_error = True
        messages.append(conf_message)
    else:
        messages.append(
            f"Public key file missing for '{client_name}', skipped direct config peer-block removal in {WG_CONF}."
        )

    removed_any_file = False
    for path in (conf_path, private_key_path, pub_key_path):
        if path.exists():
            try:
                path.unlink()
                removed_any_file = True
            except OSError as exc:
                had_error = True
                messages.append(f"Failed deleting {path}: {exc}")

    if removed_any_file:
        messages.append(f"Deleted client files for '{client_name}'.")
    else:
        messages.append(f"No client files found for '{client_name}' in {CLIENTS_DIR}.")

    status = "SUCCESS" if not had_error else "ERROR"
    return not had_error, f"{status}\n\n" + "\n".join(messages)


def _render_home_page() -> str:
    action = html.escape(STATE["last_action"])
    status = html.escape(STATE["last_status"])
    output = html.escape(STATE["last_output"])
    qr_svg = STATE["last_qr_svg"]
    qr_block = f'<section class="card" style="margin-top:16px"><h3>Client QR Code</h3><div class="qr-wrap">{qr_svg}</div></section>' if qr_svg else ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>WireGuard Client Admin</title>
  <style>
    :root {{
      --bg: #f4f6f8;
      --card: #ffffff;
      --text: #14213d;
      --accent: #005f73;
      --ok: #2b9348;
      --err: #b02a37;
      --border: #dce3e9;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--text);
      background: radial-gradient(circle at top right, #e0fbfc, var(--bg));
    }}
    .wrap {{ max-width: 960px; margin: 24px auto; padding: 0 16px; }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 4px 16px rgba(20, 33, 61, 0.08);
    }}
    label {{ display: block; margin-bottom: 8px; font-size: 14px; }}
    input {{
      width: 100%;
      padding: 10px;
      margin-top: 4px;
      border: 1px solid #c7d2dd;
      border-radius: 8px;
    }}
    button {{
      margin-top: 12px;
      border: 0;
      background: var(--accent);
      color: #fff;
      padding: 10px 14px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
    }}
    .log-title {{ margin: 0 0 8px; }}
    .status-ok {{ color: var(--ok); }}
    .status-err {{ color: var(--err); }}
    pre {{
      background: #0b132b;
      color: #edf2f4;
      padding: 12px;
      border-radius: 10px;
      overflow: auto;
      max-height: 420px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .note {{ font-size: 13px; color: #334155; }}
    a {{ color: #005f73; }}
    .qr-wrap {{
      background: #fff;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px;
      width: fit-content;
      max-width: 100%;
      overflow: auto;
    }}
    .qr-wrap svg {{
      display: block;
      width: 280px;
      height: 280px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>WireGuard Client Admin</h1>
    <p class="note">This UI runs local scripts. Start this web server with <code>sudo</code>.</p>

    <section class="card">
      <h2>Create Client</h2>
      <form method="post" action="/client">
        <label>Client Name <input name="client_name" placeholder="alice" required /></label>
        <label>Server Endpoint (DNS or IP) <input name="server_endpoint" placeholder="vpn.example.com" required /></label>
        <label>DNS Server <input name="dns_server" value="1.1.1.1" /></label>
        <label>Client IP/CIDR (optional) <input name="client_ip" placeholder="10.8.0.2/32" /></label>
        <button type="submit">Create Client</button>
      </form>
      <p class="note"><a href="/clients">View Current Clients</a></p>
    </section>

    {qr_block}

    <section class="card" style="margin-top:16px">
      <h3 class="log-title">Last Action: {action}</h3>
      <div class="{'status-ok' if status.startswith('SUCCESS') else 'status-err' if status else ''}">{status}</div>
      <pre>{output}</pre>
    </section>
  </div>
</body>
</html>
"""


def _list_client_files() -> list[Path]:
    if not CLIENTS_DIR.exists():
        return []
    return sorted(CLIENTS_DIR.glob("*.conf"))


def _render_clients_page() -> str:
    status = html.escape(STATE["last_status"])
    output = html.escape(STATE["last_output"])
    rows: list[str] = []
    for path in _list_client_files():
        name = html.escape(path.stem)
        file_path = html.escape(str(path))
        rows.append(
            f"""<tr>
<td>{name}</td>
<td><code>{file_path}</code></td>
<td>
  <form method="post" action="/clients/remove" class="remove-form">
    <input type="hidden" name="client_name" value="{name}" />
    <input name="confirm_name" placeholder="Type {name} to confirm" required />
    <button type="submit" class="danger">Remove</button>
  </form>
</td>
</tr>"""
        )

    if rows:
        table_or_message = (
            "<table><thead><tr><th>Client</th><th>Config File</th><th>Remove Client</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    else:
        table_or_message = "<p class=\"note\">No client configs found in <code>/etc/wireguard/clients</code>.</p>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>WireGuard Clients</title>
  <style>
    :root {{
      --bg: #f4f6f8;
      --card: #ffffff;
      --text: #14213d;
      --border: #dce3e9;
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--text);
      background: radial-gradient(circle at top right, #e0fbfc, var(--bg));
    }}
    .wrap {{ max-width: 960px; margin: 24px auto; padding: 0 16px; }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 4px 16px rgba(20, 33, 61, 0.08);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
    }}
    th, td {{
      text-align: left;
      padding: 10px;
      border-bottom: 1px solid var(--border);
    }}
    .note {{ font-size: 13px; color: #334155; }}
    a {{ color: #005f73; }}
    .status-ok {{ color: #2b9348; }}
    .status-err {{ color: #b02a37; }}
    .remove-form {{
      display: flex;
      gap: 8px;
      align-items: center;
    }}
    .remove-form input {{
      width: 220px;
      padding: 8px;
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .remove-form button {{
      border: 0;
      border-radius: 8px;
      padding: 8px 12px;
      color: #fff;
      cursor: pointer;
    }}
    .danger {{ background: #b02a37; }}
    pre {{
      background: #0b132b;
      color: #edf2f4;
      padding: 12px;
      border-radius: 10px;
      overflow: auto;
      max-height: 320px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Current WireGuard Clients</h1>
      <p><a href="/">Back to Client Creation</a></p>
      <div class="{'status-ok' if status.startswith('SUCCESS') else 'status-err' if status else ''}">{status}</div>
      <pre>{output}</pre>
      {table_or_message}
    </div>
  </div>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send_html(self, body: str, status: int = HTTPStatus.OK) -> None:
        content = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _parse_post(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = urllib.parse.parse_qs(data, keep_blank_values=True)
        return {k: v[0].strip() for k, v in parsed.items()}

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            self._send_html(_render_home_page())
            return
        if self.path == "/clients":
            self._send_html(_render_clients_page())
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/client":
            self._handle_client()
            return
        if self.path == "/clients/remove":
            self._handle_remove_client()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def _redirect_home(self) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.end_headers()

    def _handle_client(self) -> None:
        form = self._parse_post()
        client_name = form.get("client_name", "")
        endpoint = form.get("server_endpoint", "")
        dns_server = form.get("dns_server", "1.1.1.1")
        client_ip = form.get("client_ip", "")

        STATE["last_action"] = "Generate Client"
        STATE["last_qr_svg"] = ""

        if not NAME_RE.fullmatch(client_name):
            STATE["last_status"] = "ERROR: Invalid client name."
            STATE["last_output"] = "Use letters/numbers plus dot, underscore, dash (max 64 chars)."
            self._redirect_home()
            return
        if not HOST_RE.fullmatch(endpoint):
            STATE["last_status"] = "ERROR: Invalid endpoint host/IP format."
            STATE["last_output"] = "Use a DNS name or IP address."
            self._redirect_home()
            return
        if dns_server and not DNS_RE.fullmatch(dns_server):
            STATE["last_status"] = "ERROR: Invalid DNS server format."
            STATE["last_output"] = "Example: 1.1.1.1"
            self._redirect_home()
            return
        if client_ip and not CIDR_RE.fullmatch(client_ip):
            STATE["last_status"] = "ERROR: Invalid client IP/CIDR format."
            STATE["last_output"] = "Example: 10.8.0.2/32"
            self._redirect_home()
            return

        cmd = ["bash", str(CLIENT_SCRIPT), client_name, endpoint, dns_server]
        if client_ip:
            cmd.append(client_ip)

        ok, output = _run_script(cmd)
        STATE["last_status"] = "SUCCESS" if ok else "ERROR"
        STATE["last_output"] = _clean_output(output)
        STATE["last_qr_svg"] = ""

        if ok:
            conf_path = _extract_client_conf_path(output)
            if conf_path is not None:
                try:
                    conf_text = conf_path.read_text(encoding="utf-8")
                except OSError:
                    conf_text = ""
                if conf_text:
                    STATE["last_qr_svg"] = _generate_qr_svg_from_config(conf_text)
        self._redirect_home()

    def _handle_remove_client(self) -> None:
        form = self._parse_post()
        client_name = form.get("client_name", "")
        confirm_name = form.get("confirm_name", "")

        STATE["last_action"] = "Remove Client"
        STATE["last_qr_svg"] = ""

        if not NAME_RE.fullmatch(client_name):
            STATE["last_status"] = "ERROR: Invalid client name."
            STATE["last_output"] = "Client name format is invalid."
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/clients")
            self.end_headers()
            return

        if confirm_name != client_name:
            STATE["last_status"] = "ERROR: Confirmation failed."
            STATE["last_output"] = "Type the exact client name in the confirmation field to remove."
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/clients")
            self.end_headers()
            return

        ok, output = _remove_client(client_name)
        STATE["last_status"] = "SUCCESS" if ok else "ERROR"
        STATE["last_output"] = output
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/clients")
        self.end_headers()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple WireGuard web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not CLIENT_SCRIPT.exists():
        raise SystemExit("Required script is missing in project root.")

    with ThreadingHTTPServer((args.host, args.port), Handler) as httpd:
        print(f"WireGuard Admin UI listening on http://{args.host}:{args.port}")
        print("Use Ctrl+C to stop.")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
