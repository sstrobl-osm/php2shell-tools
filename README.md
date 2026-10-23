# php2shell-tools

Read-only triage tools for the October 2026 PHP remote-code-execution flaws:

- **PHP2Shell** — CVE-2026-109618 / CVE-2026-109619, memory-corruption RCE in PHP core (any PHP app on an unpatched 8.2–8.5).
- **CVE-2026-110447** — OS command injection in Nextcloud's built-in Collabora CODE app (`richdocumentscode`), used to drop PHP web shells.

## Scripts

| Script | What it does | Needs |
|---|---|---|
| `php_rce_logscan.py` | Scans Apache access + error logs (plain/`.gz`/`.bz2`/`.xz`) for exploit attempts, dropped web shells, worker crashes and anomalous POST activity. | Python 3.8+, stdlib only |
| `php2shell_server_sweep.sh` | **Read-only** host sweep: PHP version, web shells, suspicious processes, outbound sockets, persistence, Nextcloud app integrity. Never changes anything. | bash; run as root for full coverage |

## Usage

```bash
# Logs (set the window to your exposure period)
python3 php_rce_logscan.py /var/log/apache2/ --since 2026-10-20 --until "2026-10-21 17:00"

# Host (auto-detects Nextcloud/webroot)
sudo ./php2shell_server_sweep.sh
```

Exit codes (both): `0` nothing found · `1` review needed · `2` likely compromise.

## Important limitation

PHP2Shell delivers its payload in the **POST body, which Apache does not log**. These tools reliably catch the noisy exploit footprint, the Collabora web-shell campaign and post-exploitation traces — but a quiet, crash-free exploit can leave no trace in access logs. **A clean result is not an all-clear.** Confirm on the host, and patch PHP to **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** and restart your web workers.

## License

MIT (see `LICENSE`).
