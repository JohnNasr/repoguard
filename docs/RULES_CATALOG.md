# repoguard detection catalog (source of truth for detector modules)

Severity C/H/M/L/I = CRITICAL/HIGH/MEDIUM/LOW/INFO. Confidence H/M/L. `|` inside regexes is alternation.
Impact: **threat** (harms the person installing; drives the verdict) vs **hygiene** (harms the repo owner:
leaked keys, CVEs, CI misconfig). Hygiene rules MUST carry `tags.HYGIENE` (score contribution is capped).

## Conventions for detector authors
- Use `Rule` (declarative regex) wherever possible; use `RuleInfo` + code in `scan_file`/`scan_repo` for
  AST/JSON/TOML/structural checks. Every rule id in this file must be registered exactly once.
- Always set `keywords` (lowercase literal prefilter) on regex rules - performance depends on it.
- No nested quantifiers like `(\w+)+` or `(?:a|b+)*`, no `.*.*`; use bounded `{0,N}` gaps. Registry rejects them.
- Tags (from `repoguard/tags.py`) are the correlation contract:
  CRD* -> READS_CREDENTIALS; CRD007 -> ENV_HARVEST; EXF001-009 -> EXFIL_CHANNEL + NETWORK_SEND;
  EXF010 network sinks -> NETWORK_SEND; downloads -> DOWNLOAD; eval/exec/subprocess(shell)/iex -> EXEC_DYNAMIC;
  decoding -> DECODE; OBF* -> OBFUSCATED; INS* -> INSTALL_HOOK or OPEN_HOOK; MAL003/004 -> PERSISTENCE;
  MAL008/009 -> AV_TAMPER; MAL001 -> REVERSE_SHELL; MAL005 -> MINER; MAL010 -> PROCESS_INJECTION;
  MAL006/007/CRD008 -> SURVEILLANCE; MAL011 -> ANTI_ANALYSIS; PHI* -> PHISHING; AIX002/009/010 -> AI_INSTRUCTION;
  AIX006-008 -> INVISIBLE_UNICODE; SEC* -> SECRET + HYGIENE; BIN001-003/006/008 -> BINARY_EXEC;
  DEP* -> DEPENDENCY_RISK (+TYPOSQUAT for DEP001); CIX* -> CI_RISK (+HYGIENE except CIX003); FSX* -> FS_TRICK.
- `tags.NO_DAMPEN` = location (test/doc/vendored) must not lower the score. Put it on high-signal rules:
  all EXF001-009, all MAL, OBF001-004, AIX006-008, INS013 (README pipe-to-shell), INS015 (conftest/.pth auto-load).
- `tags.BLOCK_TRIGGER` = forces verdict BLOCK. Only on: MAL001, MAL002, MAL005, MAL008, MAL013 (when confidence H),
  DEP002 (OSV MAL- id), CRD010. Correlations (COR*) are owned by the lead, not by detector modules.
- Global FP controls ("std-FP"): placeholders (`textutil.is_placeholder`), AWS doc key `AKIAIOSFODNN7EXAMPLE`,
  entropy floors, `ctx.is_test/is_doc/is_vendored` lower confidence one level for non-high-signal rules
  (pass `confidence=` when building the Finding), detection-rule-list files (>40% of lines are regex/IOC
  literals) get lower confidence. Never exclude files by name inside the scanned repo.
- Snippets: pass the raw line; `Finding.from_rule` sanitizes. For secrets pass `secret=value` so it is masked.

## SEC - committed secrets (hygiene; severity H/M; tag SECRET+HYGIENE; module secrets.py)
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| SEC001 | Anthropic | `sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}` | H | H |
| SEC002 | OpenAI | `sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}` and `sk-proj-[A-Za-z0-9_-]{80,}` | H | H |
| SEC003 | Google | `AIza[0-9A-Za-z_-]{35}`; `GOCSPX-[A-Za-z0-9_-]{28}`; JSON with `"type": "service_account"` + `"private_key"` | H | H |
| SEC004 | AWS | `\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`; secret `(?i)aws.{0,25}(secret|sk).{0,25}['"][A-Za-z0-9/+=]{40}['"]` | H | H |
| SEC005 | Azure | storage conn string `AccountKey=[A-Za-z0-9+/=]{86,88}`; client secret `[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}`; SAS `[?&]sig=[A-Za-z0-9%]{40,}` | H | M |
| SEC006 | GitHub | `\bgh[pousr]_[A-Za-z0-9]{36,255}\b`, `github_pat_[A-Za-z0-9_]{82}` | H | H |
| SEC007 | Slack | `xox[abprs]-[A-Za-z0-9-]{10,}`; webhook `hooks\.slack\.com/services/T\w+/B\w+/\w{24}` | H | H |
| SEC008 | Stripe | `\b(?:sk|rk)_live_[A-Za-z0-9]{24,}` (H); `_test_` (L); `whsec_[A-Za-z0-9]{32,}` | H | H |
| SEC009 | Discord bot token | `[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}` | H | M |
| SEC010 | Telegram bot token | `\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b` | H | H |
| SEC011 | Private key | `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----` | H | H |
| SEC012 | JWT | `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`; decode payload, L if `exp` passed | M | M |
| SEC013 | DB URL with password | `(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^:\s/@]+:[^@\s/]{3,}@[^\s/]+`; drop trivial pw on localhost | M | M |
| SEC014 | committed .env | file `.env`/`.env.*` (not .example/.sample/.template/.dist) with >=1 `KEY=value` entropy >= 3.5 | M | H |
| SEC015 | Other providers | `hf_[A-Za-z]{34}`, `npm_[A-Za-z0-9]{36}`, `pypi-AgEIcHlwaS5vcmc[\w-]{50,}`, `glpat-[\w-]{20}`, `SG\.[\w-]{22}\.[\w-]{43}`, `gsk_[A-Za-z0-9]{52}`, `xai-[A-Za-z0-9]{80}`, Twilio `AC[0-9a-f]{32}`/`SK[0-9a-f]{32}` (needs "twilio" context), Mailgun `key-[0-9a-f]{32}` (context) | H | M |
| SEC016 | Generic high-entropy assignment | `(?i)(api[_-]?key|secret|token|passw(?:or)?d|auth|credential|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{16,})["']`; keep if entropy >= 4.0 (or >= 3.0 for hex) and value not identifier/path/URL | M | L |
Dedupe same value. Keys in docs: still reported, confidence L.

## CRD - credential theft sources (threat; tag READS_CREDENTIALS; module exfil.py)
Each alone is M/L; correlation with a network sink makes it critical (lead's COR001).
| ID | Target | Logic | Sev | Conf |
|---|---|---|---|---|
| CRD001 | SSH | `\.ssh[/\\]+(id_\w+|authorized_keys|config|known_hosts)`; AST `join(home,'.ssh')`, `expanduser('~/.ssh...')` | M | M |
| CRD002 | CLI & AI creds | `\.aws[/\\]credentials`, `\.azure[/\\]`, `application_default_credentials\.json`, `gh[/\\]hosts\.yml`, `\.docker[/\\]config\.json`, `\.kube[/\\]config`, `\.npmrc`, `\.pypirc`, `\.git-credentials`, `\.netrc`, `\.claude[/\\]\.credentials\.json`, `\.codex[/\\]auth\.json`, `\.config[/\\](openai|anthropic|gcloud)` | M | M |
| CRD003 | Browser stores | `Login Data`, `Web Data`, `Local State`, `key4\.db`, `logins\.json`, `cookies\.sqlite`, `(Google[/\\]Chrome|BraveSoftware|Microsoft[/\\]Edge|Opera Software)[/\\]`, `Firefox[/\\]Profiles`, `CryptUnprotectData`, `encrypted_key` | H | H |
| CRD004 | Crypto wallets | `wallet\.dat`, `Exodus`, `Electrum`, `Atomic Wallet`, MetaMask id `nkbihfbeogaeaoehlefnkodbefgpgknn`, Phantom `bfnaelmomeimhlpmgjnjophhpkkoljpa`, seed phrase/mnemonic near file reads | H | M |
| CRD005 | Discord/Telegram/Steam sessions | `discord(canary|ptb)?[/\\]Local Storage[/\\]leveldb`, `dQw4w9WgXcQ:`, `tdata[/\\]`, `ssfn` | H | H |
| CRD006 | Keychain/vault | `security (find-generic-password|dump-keychain)`, `CredEnumerate`, `cmdkey /list`, `vaultcmd`, `secret-tool lookup`; `keyring.get_password` at L | M | M |
| CRD007 | Environment dump (tag ENV_HARVEST) | AST `dict(os.environ)`, `os.environ.copy()`, iterating `os.environ.items()`, `json.dumps(os.environ)`; JS `JSON.stringify(process.env)`, `Object.(entries|keys)(process.env)`; shell `\b(env|printenv)\b\s*\|` | M | M |
| CRD008 | Clipboard (tag SURVEILLANCE) | `pyperclip.paste`, `GetClipboardData`, `Get-Clipboard`, `navigator.clipboard.readText`; H when crypto-address regex + clipboard write (clipper) | M | M |
| CRD009 | Sensitive file sweep | home walk/glob + list with >=3 of {`.env`,`id_rsa`,`.pem`,`wallet`,`credentials`,`.kdbx`,`token`} | H | M |
| CRD010 | OS credential dump (BLOCK_TRIGGER) | `/etc/shadow`, `reg save HKLM\\(SAM|SYSTEM|SECURITY)`, `comsvcs(\.dll)?.{0,40}MiniDump`, `procdump.{0,20}lsass`, `sekurlsa` | C | H |

## EXF - exfiltration channels (threat; module exfil.py; NO_DAMPEN on 001-009)
| ID | Detects | Regex | Sev | Conf |
|---|---|---|---|---|
| EXF001 | Discord webhook | `discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w-]{60,}` | H | H |
| EXF002 | Telegram bot API | `api\.telegram\.org/bot` + `send(Message|Document|Photo)|getUpdates` | H | H |
| EXF003 | Slack/Teams webhook | slack webhook; `\.webhook\.office\.com` | M | M |
| EXF004 | Paste/file drop | `pastebin\.com/(api|raw)|paste\.ee|hastebin|transfer\.sh|file\.io|0x0\.st|gofile\.io|catbox\.moe|temp\.sh|bashupload|anonfiles|ufile\.io` | H | M |
| EXF005 | Tunnel/request catcher/OAST | `ngrok(-free)?\.(io|app)|trycloudflare\.com|serveo|localhost\.run|loca\.lt|webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator|beeceptor` | H | M |
| EXF006 | Raw public IP URL | `\b(?:https?|wss?|tcp)://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?` excluding RFC1918, loopback, link-local, 0.0.0.0 and documentation ranges | M | M |
| EXF007 | DNS exfil | dynamically built hostname (f-string/concat with encoded var) passed to `gethostbyname|getaddrinfo|dns\.(resolve|lookup)|nslookup|Resolve-DnsName` | H | M |
| EXF008 | Dynamic DNS | `duckdns\.org|no-ip|ddns\.net|hopto\.org|zapto\.org|portmap\.io` | M | M |
| EXF009 | SMTP with hard-coded creds | `smtplib.SMTP` + `.login(` with literal args; nodemailer auth literal | M | M |
| EXF010 | Network sink (INFO, for correlation; tag NETWORK_SEND, DOWNLOAD where it fetches) | `requests\.(post|put|get)`, `urlopen`, `http\.client`, `socket\.connect`, `fetch\(`, `axios`, `XMLHttpRequest`, `https?\.request`, `Invoke-(WebRequest|RestMethod)`, `Net\.WebClient`, `curl .{0,80}(-d|-F|--data|-T)`, `wget --post` | I | H |
Webhooks in docs/tests still reported at M (a real webhook URL is live).

## PHI - API-key phishing (threat; tag PHISHING; module exfil.py)
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| PHI001 | Prompt for secret then send | AST: `input()`/`getpass()` prompt matching `(?i)api[ _-]?key|token|secret|password|seed|mnemonic|private key` + network sink in same function to a host not in provider allowlist | H | M |
| PHI002 | HTML form collecting keys | `<input` name/id/placeholder matching key regex or `sk-...`, form action / fetch to external host not in allowlist | H | M |
| PHI003 | Key sent to wrong host | `*_API_KEY`/`*_TOKEN` var used in a request whose host doesn't match provider (ANTHROPIC_* -> api.anthropic.com, OPENAI_* -> api.openai.com ...). `base_url` override to unknown host = M; known gateways (openrouter.ai, *.openai.azure.com, together, groq, localhost, ollama) = I | H | M |
| PHI004 | Brand login clone | HTML with GitHub/Google/Microsoft/Apple/Binance/MetaMask branding + password field posting off-brand | H | M |
| PHI005 | Social engineering | README/docs: `(?i)(paste|enter|send|submit).{0,40}(api key|token|seed phrase|private key)` near a URL | M | L |

## OBF - obfuscation (threat; tag OBFUSCATED (+DECODE/EXEC_DYNAMIC); module obfuscation.py)
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| OBF001 | Python decode->exec | AST: arg of `exec|eval|compile|__import__|getattr(builtins,..)|types.FunctionType|marshal.loads` built from `b64decode|b32decode|b85decode|a85decode|bytes.fromhex|codecs.decode|zlib|lzma|bz2|gzip.decompress|pickle.loads|''.join(chr..)|[::-1]`; chain >= 2 = C (use repoguard.pyast) | C | H |
| OBF002 | JS decode->exec | in one statement (<= 400 chars): `\b(eval|Function|setTimeout|setInterval|vm\.run\w*|execSync)\s*\(` with `atob|Buffer\.from\([^)]*,\s*['"](base64|hex)|String\.fromCharCode|unescape|\\x[0-9a-f]{2}` runs | C | H |
| OBF003 | Packers | `eval\(function\(p,a,c,k,e,[dr]\)`, `_0x[a-f0-9]{4,6}` 20+ times, JSFuck `[\[\]()!+]{200,}`, aaencode/jjencode | H | H |
| OBF004 | PowerShell | `(?i)-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}` (strip backtick and ^ first); decode UTF-16LE base64 and rescan; `FromBase64String`, `\biex\b|Invoke-Expression`, `-w(indowstyle)? h(idden)?`, `-ep bypass`, `-nop`, `[char[]]...-join` | H | H |
| OBF005 | Large encoded blob | base64 >= 200 / hex >= 400 chars in code: decode, sniff magic (MZ, ELF, PK, gzip, script shebang, pyc), rescan decoded text recursively (depth 3, 5 MB cap) with the other OBF/MAL/EXF regexes; decoded executable/script = H | M | M |
| OBF006 | Hidden code via whitespace/long lines | line with >= 150 spaces then code (`[;:]\s*\S`, `import`, `exec`); lines > 1000 chars in .py/.sh/.ps1, or .js that isn't minified/vendored | H | H |
| OBF007 | Entropy | text source file entropy > 5.5; string literal > 100 chars with entropy > 4.5 | M | L |
| OBF008 | Homoglyph identifiers | Python AST names / JS identifiers mixing Latin with Cyrillic/Greek (unicodedata.name prefix); non-ASCII import names | H | M |
| OBF009 | Dynamic resolution | `getattr(__builtins__|builtins, <non-literal>)`, `__import__(<non-literal>)`, `importlib.import_module(<decoded>)`, JS `require(<computed>)`, `global[...]`/`globalThis[...]` calls | M | M |
| OBF010 | Commercial packed Python | `__pyarmor__|pyarmor_runtime|PyObfuscator|Hyperion`, `exec((lambda`, nested lambda chains | H | M |
| OBF011 | Unusual source encoding | PEP 263 coding not in {utf-8, ascii, latin-1}; UTF-16/32 source (ctx.encoding) | M | H |
In dist/ *.min.js / vendored: drop one level unless OBF001/002/004.

## INS - install/open-time execution (threat; module exec_hooks.py; tag INSTALL_HOOK or OPEN_HOOK)
| ID | Surface | Logic | Sev | Conf |
|---|---|---|---|---|
| INS001 | npm lifecycle | package.json (json.loads) scripts `preinstall, install, postinstall, prepare, preuninstall, prepack`. Allowlist -> I: `husky( install)?`, `node-gyp rebuild`, `prebuild-install`, `patch-package`, `tsc`, `ngcc`. H if body matches `node -e|curl|wget|powershell|bash -c|https?:|base64|eval`. Mention referenced script file in description | M | H |
| INS002 | setup.py | AST of module level + `cmdclass` subclasses of install/develop/egg_info/build_py: network, subprocess, `os.system`, exec/eval, decoding, writes outside build dir | H | H |
| INS003 | pyproject build backend | `build-backend` not in {setuptools.build_meta, hatchling.build, flit_core.buildapi, poetry.core.masonry.api, pdm.backend, maturin, scikit_build_core.build, mesonpy}, or `backend-path` set; `requires` with URL/git deps (tomllib) | M | H |
| INS004 | Make/CMake/just/Taskfile | network or exec patterns; CMake `execute_process|file\(DOWNLOAD` | M | M |
| INS005 | Cargo build.rs / proc-macro | `reqwest|ureq|TcpStream|Command::new`, writes outside `OUT_DIR`, `include_bytes!` of binary | H | M |
| INS006 | binding.gyp | `<!(` / `<!@(` command expansion, `actions` running scripts | M | M |
| INS007 | Other ecosystems | composer `post-(install|update)-cmd`, gemspec `extensions`/extconf.rb, `.csproj` and auto-imported `Directory.Build.(props|targets)` `<Exec Command=`, NuGet `tools/init.ps1`, Gradle `exec|URL(`, Maven exec plugin, `go:generate` (L) | M | M |
| INS008 | VS Code (OPEN_HOOK) | tasks.json `"runOn"\s*:\s*"folderOpen"` (H). settings.json keys `terminal.integrated.(env|shell|profiles|automationProfile)`, `*.(path|executablePath|serverPath|runtime)` / `python.defaultInterpreterPath` pointing in-repo, `task.allowAutomaticTasks`, `security.workspace.trust` (M). launch.json preLaunchTask (L). Parse JSONC (strip // and /* */ comments, trailing commas) | H | H |
| INS009 | devcontainer (OPEN_HOOK) | `initializeCommand` runs on HOST (H); `onCreateCommand|postCreateCommand|postStartCommand|postAttachCommand` (M); features from non `ghcr.io/devcontainers` sources | H | H |
| INS010 | JetBrains | `.idea/**` startup tasks, external tools, run configs executing scripts | M | M |
| INS011 | Git hooks | committed `.githooks/`, `.husky/`, `hooks/` + `git config core.hooksPath` in scripts/README; `.pre-commit-config.yaml` with `repo: local` or unusual repos | M | M |
| INS012 | Docker | `(curl|wget)[^\n]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh`, `ADD https?://`, `privileged: true`, mounts of `/`, `docker.sock`, `~/.ssh`, `network_mode: host` | M | M |
| INS013 | README pipe-to-shell (NO_DAMPEN) | `(curl|wget)[^\n]{0,200}\|\s*(sudo\s+)?\w*sh\b`, `bash <\(curl`, `(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)[^\n]{0,200}\|\s*iex`, `mshta https?:`, `certutil.{0,20}-urlcache`. M if first-party host (raw.githubusercontent.com, *.github.io, project domain); H if third-party, raw IP, URL shortener, paste site. ClickFix `(?i)(win\s*\+\s*r|run dialog).{0,80}(paste|ctrl\s*\+\s*v)` = H | M | M |
| INS014 | Setup scripts | `install*.sh`, `setup*.ps1`, `bootstrap*`, root `*.bat`: writes to `.bashrc`, `.zshrc`, `$PROFILE`; PATH prepend; `chmod [u+]s` | M | M |
| INS015 | Import-time hooks (NO_DAMPEN) | `.pth` with a line starting `import` (H); `sitecustomize.py`/`usercustomize.py` (H); `conftest.py` or package `__init__.py` with module-level network/exec (H); `.yarnrc.yml` `yarnPath` -> committed JS (M); `.npmrc` `script-shell|node-options` (M); `.envrc` (M) | H | H |
| INS016 | Notebooks | `.ipynb` cells with `!curl...|sh`, `%run` remote, `!pip install` from URL/index | M | M |

## CIX - CI/CD (module cicd.py; tag CI_RISK; HYGIENE except CIX003). YAML via line/regex parsing.
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| CIX001 | Pwn request | `on:` has `pull_request_target|workflow_run` AND checkout `ref:.*github\.event\.(pull_request\.head\.(sha|ref)|workflow_run\.head)` or `refs/pull/` | M | H |
| CIX002 | Script injection | `run:` containing `\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit|commits)[^}]{0,80}(title|body|message|name|label|ref)|head_ref)` | M | H |
| CIX003 | Secret exfiltration (threat, NO HYGIENE) | `toJSON\(secrets\)`; `secrets\.` in same step as curl/wget/nc to external host; `secrets\.\w+.{0,40}base64`; `/proc/\d*/mem` or `Runner.Worker` memory read (C) | H | H |
| CIX004 | Unpinned 3rd-party actions | `uses:\s*` not `actions/` or `github/` and ref not 40-hex SHA (L); known-compromised list e.g. `tj-actions/changed-files`, `reviewdog/action-setup` (M) | L | H |
| CIX005 | Self-hosted runner | `runs-on:.{0,40}self-hosted` | L | M |
| CIX006 | Broad permissions | `permissions:\s*write-all`, `contents: write` on PR triggers | L | M |
| CIX007 | Remote script in CI | pipe-to-shell (INS013 regexes) in workflow/GitLab/Azure/CircleCI files | M | M |

## MAL - malware behaviours (threat; module malware.py; NO_DAMPEN on all)
| ID | Behaviour | Indicators | Sev | Conf |
|---|---|---|---|---|
| MAL001 | Reverse shell (REVERSE_SHELL, BLOCK_TRIGGER) | AST `os.dup2(s.fileno(),0..2)` + `pty.spawn`/subprocess shell; `/dev/tcp/`; `\bn(c|cat)\b.{0,20}-e\b`; `mkfifo.{0,40}\bnc\b`; `Net\.Sockets\.TCPClient` + `GetStream` + iex; JS `net.Socket` + spawn('/bin/sh'|'cmd.exe') pipe | C | H |
| MAL002 | Download + execute (DOWNLOAD+EXEC_DYNAMIC, BLOCK_TRIGGER) | fetch then write then exec/`chmod +x`/`os.startfile`/`Start-Process` same file; `urlretrieve` + subprocess; `DownloadFile` + `Start-Process`; `certutil -urlcache -f`, `bitsadmin /transfer`, `regsvr32 /i:http`, `rundll32 .{0,40}javascript:` | C | H |
| MAL003 | Windows persistence | `CurrentVersion\\Run(Once)?`, `schtasks\s+/create`, `Register-ScheduledTask`, `Start Menu\\Programs\\Startup`, `shell:startup`, `__EventFilter`, `sc(\.exe)? create|New-Service`, `Image File Execution Options`, `Winlogon.{0,30}(Userinit|Shell)` | H | H |
| MAL004 | Unix/mac persistence | `crontab\s+-`, `/etc/cron`, `LaunchAgents|LaunchDaemons`, `launchctl (load|bootstrap)`, `systemctl (--user )?enable`, writes to `~/.config/systemd`, `>>\s*~?/?\.?(bashrc|zshrc|profile)`, authorized_keys append, `ld\.so\.preload|LD_PRELOAD=` | H | H |
| MAL005 | Crypto miner (MINER, BLOCK_TRIGGER) | `stratum\+(tcp|ssl|tls)://`, `xmrig`, `cryptonight`, `randomx`, `--donate-level`, pools `supportxmr|moneroocean|nanopool|2miners|hashvault|f2pool`, XMR address `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b` | C | H |
| MAL006 | Keylogger | `pynput.keyboard.Listener`, `keyboard.(hook|on_press)`, `SetWindowsHookEx\w*` with `13|WH_KEYBOARD_LL`, `GetAsyncKeyState`, `iohook|uiohook` | M | M |
| MAL007 | Screen/cam/mic | `ImageGrab.grab`, `mss\(`, `pyautogui.screenshot`, `BitBlt` + `GetDC(0|None)`, `cv2.VideoCapture\(0\)`, `screencapture -x`, `desktopCapturer`, `sounddevice.rec` | L | M |
| MAL008 | Defense evasion (AV_TAMPER, BLOCK_TRIGGER) | `Set-MpPreference\s+-Disable`, `Add-MpPreference\s+-Exclusion`, `DisableAntiSpyware`, `(sc|net) stop WinDefend`, `advfirewall.{0,30}state off`, `vssadmin.{0,10}delete shadows`, `wevtutil cl`, `bcdedit.{0,40}recoveryenabled no`, `AmsiUtils|amsiInitFailed|AmsiScanBuffer`, `EtwEventWrite` patch | C | H |
| MAL009 | UAC bypass / privesc (AV_TAMPER) | `ms-settings\\Shell\\Open\\command`, `mscfile\\shell\\open\\command`, `DelegateExecute`, `fodhelper|computerdefaults|sdclt|eventvwr` + registry write; `-Verb RunAs`/`sudo` in install hooks = M | H | H |
| MAL010 | Process injection (PROCESS_INJECTION) | `VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext|NtUnmapViewOfSection|RtlCreateUserThread` (>=2 distinct = H, 1 = M); ctypes `VirtualAlloc` + `RtlMoveMemory` + `CreateThread` on byte literal >= 200 bytes = C | H | H |
| MAL011 | Anti-analysis / env-keyed (ANTI_ANALYSIS) | `IsDebuggerPresent|CheckRemoteDebuggerPresent`, `(?i)vbox|vmware|qemu|sandboxie|SbieDll|WDAGUtilityAccount`, MAC `08:00:27`, analyst process lists (`wireshark|procmon|x64dbg|ida64`), sleep >= 600 s, branching on `CI`/`GITHUB_ACTIONS` env or locale/geo to skip | H | M |
| MAL012 | Destructive / ransomware | `rm\s+-rf\s+(/|~|\$HOME)(\s|$)`, `rmtree\(.{0,40}expanduser`, `format [a-z]:`, `cipher /w`, `dd if=/dev/(zero|urandom) of=/dev/`, ransom-note phrases | C | M |
| MAL013 | Worm / self-propagation (BLOCK_TRIGGER) | reads npm/PyPI/GitHub token AND `npm publish`/`twine upload`/GitHub API repo/workflow creation in the same file; downloading trufflehog/gitleaks to harvest | C | H |
| MAL014 | System trust tampering | `drivers\\etc\\hosts`, `/etc/hosts` writes, `certutil.{0,20}-addstore.{0,10}root`, `add-trusted-cert`, proxy/DNS changes | H | M |
| MAL015 | Bot C2 | Telegram `getUpdates` or Discord gateway polling feeding `exec|subprocess|eval` in same file | C | H |
Security-research/red-team repos (README/topics `malware-analysis|red-team|ctf|pentest`) legitimately contain these: still report; the LLM triage judges.

## AIX - AI tool attack surface (module ai_surface.py)
Scope: ctx.is_ai_config files (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .cursor/rules/**, .windsurfrules, .clinerules, .roo/**, .continue/**, .github/copilot-instructions.md, .github/instructions/**, .claude/**, .mcp.json, .cursor/mcp.json, .vscode/mcp.json, .claude-plugin/**, SKILL.md). Other files get lower severity.
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| AIX001 | Instruction files present | inventory, one INFO per file | I | H |
| AIX002 | Injection phrasing (AI_INSTRUCTION) | `(?i)\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|all|system)\b.{0,20}\b(instructions?|rules|prompts?)`; `(?i)\byou are now\b`; `(?i)do not (tell|inform|mention|reveal|show).{0,30}\b(user|human)`; `(?i)\b(silently|quietly|without (asking|confirmation|telling))`; `(?i)(run|execute|call).{0,40}(curl|wget|iwr|bash|powershell|npx)`; `(?i)dangerously-skip-permissions|bypassPermissions|--yolo|auto-?approve`; `<\|?(system|im_start|assistant)`; mentions of `.env`, `~/.ssh`, credentials. H in AI config files, M elsewhere (docs/code comments) | H | M |
| AIX003 | Claude settings | `.claude/settings(.local)?.json` (json): any `hooks.*[].hooks[].command` (SessionStart/UserPromptSubmit/PreToolUse... hook = M; H if network/encoding/out-of-repo path); `env.ANTHROPIC_BASE_URL`/`*_BASE_URL` to non-Anthropic host = C (redirects auth); `apiKeyHelper`, `statusLine.command`, `otelHeadersHelper`, `awsAuthRefresh` (M/H by content); `permissions.defaultMode: bypassPermissions`, allow `Bash(*)`/`Bash(curl:*)`, `enableAllProjectMcpServers: true` (H). Tag OPEN_HOOK | H | H |
| AIX004 | MCP configs | each server in `.mcp.json`/mcp.json (`mcpServers` or `servers`): `command` npx/uvx/bunx/pipx/docker with unpinned/unknown package, `-y`; command pointing to in-repo script; remote `url`; env referencing secrets. Tag OPEN_HOOK | M | M |
| AIX005 | Skills/agents/commands/plugins | AIX002 on bodies; `` !`...` `` inline bash in slash commands; `allowed-tools` with broad Bash; plugin `hooks/hooks.json` treated like AIX003; | M | M |
| AIX006 | Unicode tag chars (NO_DAMPEN) | `[\U000E0000-\U000E007F]`; decode to ASCII (textutil.decode_tag_chars) and include escaped decoded text in description. C in AI config files, H elsewhere | C | H |
| AIX007 | Invisible/format chars (NO_DAMPEN) | zero-width etc. (textutil.find_invisible, excluding bidi and tags) in code or AI config; variation-selector runs `[\uFE00-\uFE0F\U000E0100-\U000E01EF]{4,}` | H | M |
| AIX008 | Bidi Trojan Source (NO_DAMPEN) | `[\u202A-\u202E\u2066-\u2069]` in source files (H). L in i18n/.po files or when neighbours are Arabic/Hebrew script | H | H |
| AIX009 | Hidden markdown (AI_INSTRUCTION) | `<!--...-->` (multiline), `[//]: # (...)`, `display:\s*none`, `font-size:\s*0`, 200+ whitespace padding; run AIX002 phrases on extracted text. Any imperative aimed at an AI inside hidden text = H | M | M |
| AIX010 | Text addressing AI or scanners (AI_INSTRUCTION, EVASION) | `(?i)(ai|llm|assistant|claude|copilot|cursor|gpt|reviewer|scanner|security tool).{0,60}(must|should|ignore|safe|false positive|approved|verified)` in comments, strings or docs | H | M |
| AIX011 | Homoglyph instruction file names | path NFKC/confusable skeleton equals a known instruction file name but bytes differ | H | H |

## FSX - filesystem tricks (module fs_tricks.py; mostly scan_repo over repo.special + repo.files; tag FS_TRICK)
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| FSX001 | Symlinks | SpecialEntry kind symlink/junction (I). Target escapes root after normalization (H); target is sensitive (`.ssh`, `/etc`, `C:\Users`, `%APPDATA%`, `~`) (C) | H | H |
| FSX002 | Path traversal names | `..` components, absolute paths, drive letters, `:` (NTFS ADS), backslashes in names | H | H |
| FSX003 | Reserved / .git spoofing | `(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`, trailing dot/space, `(?i)^\.git[\. ]+$|^git~\d`; SpecialEntry reserved_name | H | H |
| FSX004 | Case/normalization collisions | two paths equal under casefold+NFC | M | H |
| FSX005 | Bombs/huge files | file > 50 MB; zip ratio > 100:1 or declared size > 1 GB; nesting > 3 (zipfile.infolist only) | M | H |
| FSX006 | Submodules | `.gitmodules`: url starting `-`, `ext::`, `file://`, `http://`; path containing `..` (H); others listed (I, not recursed); SpecialEntry submodule | H | H |
| FSX007 | .gitattributes | `filter=`/`diff=`/`merge=` custom drivers (M); `filter=lfs` (I, coverage gap); `export-ignore`, `linguist-generated`, `linguist-vendored` on first-party code paths (M) | M | M |
| FSX008 | Hostile local .git | local scans: read `<root>/.git/config` as TEXT (never run git with it): `core.(fsmonitor|sshCommand|pager|editor|hooksPath|askPass)`, `[include]`, `[includeIf`, `filter.*.(clean|smudge|process)`, `diff.*.textconv`, `credential.helper`; non-`.sample` files in `.git/hooks` | C | H |
| FSX009 | File missing after checkout | SpecialEntry missing_checkout: in git tree but not on disk (antivirus quarantine or invalid name) | H | M |
| FSX010 | Nested .git directory | SpecialEntry nested_git (fake submodule / hidden repo) | M | M |

## BIN - binaries and artifacts (module binaries.py; use ctx.head magic bytes; tag BINARY_EXEC)
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| BIN001 | Executables | magic `MZ` (+ check `PE\0\0` at e_lfanew), `\x7fELF`, Mach-O `FEEDFACE/FEEDFACF/CEFAEDFE/CFFAEDFE`, fat `CAFEBABE` (not .class) regardless of extension; L under test fixtures | M | H |
| BIN002 | Native modules | `.node .so .dylib .dll .pyd` esp. without build source (binding.gyp, setup ext_modules, Cargo) | M | H |
| BIN003 | Orphan bytecode | `.pyc` / `__pycache__` with no sibling `.py` | H | H |
| BIN004 | Java | `.jar .war .class` (gradle-wrapper.jar = I) | M | M |
| BIN005 | Archives | zip, tar, gz, 7z, rar, cab, iso, img, vhd(x): list contents with zipfile/tarfile (NO extraction). Encrypted zip (flag bit 0) = H; executables inside, nested archives, zip-slip names raise | M | H |
| BIN006 | Magic/extension mismatch | image/font/text/data extension whose magic is PE, ELF, zip or a script shebang | H | H |
| BIN007 | Deceptive names | `\.(pdf|docx?|xlsx?|jpe?g|png|txt|mp4)\.(exe|scr|bat|cmd|com|pif|vbs|jse?|wsf|hta|lnk|ps1|msi)$`, RTLO U+202E in name (C), trailing dot/space | H | H |
| BIN008 | Windows launchers | `.lnk .scr .hta .cpl .reg .xll .sct .library-ms .search-ms .url .application` (H); `.bat .cmd .vbs .vbe .wsf .ps1 .msi .msix .chm` (M); Office macro `.docm/.xlsm` or OLE `D0CF11E0` with `VBA` stream marker (H) | H | H |
| BIN009 | Appended payload | > 1 KB after PNG `IEND` chunk or JPEG `FFD9`; polyglots | M | M |

## DEP - dependencies & supply chain (modules dependencies.py, depparse.py; tag DEPENDENCY_RISK)
| ID | Detects | Logic | Sev | Conf |
|---|---|---|---|---|
| DEP001 | Typosquat (TYPOSQUAT) | manifests: package.json (all dep maps), requirements*.txt, pyproject (PEP 621 + poetry), Pipfile, setup.py (AST literals of install_requires), Cargo.toml, go.mod, Gemfile, composer.json. Compare to bundled top lists (`repoguard/data/top_npm.txt`, `top_pypi.txt`, PEP 503 normalized). Damerau-Levenshtein <= 1 (len >= 5) or <= 2 (len >= 10); separator swaps; `py`/`python-`/`node-`/`-js` affixes; homoglyphs (rn->m, 1->l, 0->o); scope confusion. Skip names that are themselves popular | M | M |
| DEP002 | Known malicious (BLOCK_TRIGGER) | online OSV `https://api.osv.dev/v1/querybatch` by ecosystem+name(+version); `MAL-` ids = C; offline: bundled list `repoguard/data/malicious_packages.txt` (ecosystem:name) of well-known historical malicious names | C | H |
| DEP003 | Known vulnerable (HYGIENE) | OSV CVE/GHSA on pinned/locked versions | L | H |
| DEP004 | Non-registry sources | `git\+|github:|git://|https?://.{0,200}\.(tgz|tar\.gz|zip|whl)`, `file:\.\./`, raw IPs, `http://`; requirements `--(extra-)?index-url|-i |--trusted-host|-f |--find-links`; `.npmrc` `registry=`/`@scope:registry=`, `.yarnrc*` `npmRegistryServer`, pip.conf/pip.ini, uv.toml / `[[tool.uv.index]]`, poetry sources, `.cargo/config.toml` `replace-with`, NuGet.config, GOPROXY/GOFLAGS/GONOSUMDB | M | H |
| DEP005 | Dependency confusion | `--extra-index-url` (M); online: dep absent on public registry while an extra index is configured (H) | M | M |
| DEP006 | Lockfile integrity | package-lock/yarn.lock/pnpm-lock `resolved` hosts other than registry.npmjs.org / registry.yarnpkg.com / declared registry; missing `integrity`; poetry/uv/Cargo lock sources off default registry | H | H |
| DEP007 | Loose pins (HYGIENE) | `*`, `latest`, open-ended `>=`, no lockfile | L | H |
| DEP008 | Committed dependency trees | committed `node_modules/`, `site-packages/`, `vendor/` with packages; nested `scripts.install` inside them | M | M |
| DEP009 | Recent dependencies (online) | npm `time.created` / PyPI upload_time < 30 days | L | M |

## REP - reputation (module reputation.py; needs_network=True; `gh api` via repo.net.gh_api; only when repo.is_remote and GitHub URL)
| ID | Signal | Logic | Sev | Conf |
|---|---|---|---|---|
| REP001 | Star farming | created < 60 days and stars/day > 50 with forks+issues < 2% of stars (optionally sample stargazers: >50% accounts < 30 days old, 0 followers) | M | M |
| REP002 | Fork payload | `fork: true`: GET `repos/{o}/{r}/compare/{parent_owner}:{branch}...{owner}:{branch}`; changed files touching install hooks/binaries/AI config = H | H | M |
| REP003 | Impersonation | repo name matches bundled top-repo map (`repoguard/data/top_repos.txt`: name owner) but owner differs and not a fork; lure words `(?i)crack(ed)?|free|unlock(ed)?|keygen|cheat|aimbot|spoofer|generator|bypass|premium` in name/description | H | M |
| REP004 | Throwaway owner | account < 90 days, 0 followers | M | M |
| REP005 | Release lure | releases with .exe/.zip/.rar/.7z assets but no build workflow; README `(?i)password\s*[:=]\s*\S+` near a download link (offline check on README too) | M | M |
| REP006 | Commit anomalies | single huge initial commit by new account; dormant repo whose latest commit only touches hooks/binaries | M | L |
| REP007 | README lure (offline, on README files) | `mediafire|mega\.nz|dropbox\.com/s|bit\.ly|tinyurl|cutt\.ly|cdn\.discordapp\.com/attachments`; `(?i)(disable|turn off|whitelist|exclude).{0,30}(antivirus|defender|av\b)|false positive` | H | H |

## HIS / COR (lead-owned: history.py, correlate.py) - listed for reference
HIS001 secrets in git history (hygiene), HIS002 payload present in history but removed at HEAD.
COR001 credential source + exfil/network in same file -> C BLOCK; COR002 decode->exec + network -> C dropper;
COR003 install hook + network/exec/obfuscation -> C; COR004 env dump + network -> C; COR005 surveillance + exfil -> C;
COR006 anti-analysis + malware/exfil/obfuscation -> C BLOCK; COR007 persistence + download-exec/obfuscation -> C;
COR008 AI injection + exec/secret/network in same AI config file -> C; COR009 binary + referenced from hooks/README;
COR010 README lure + reputation red flags -> C BLOCK; COR012 phishing + network -> C; COR013 invisible/hidden + exec;
COR014 text addressing reviewers + any H finding -> escalate.
