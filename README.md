# repoguard

Check a GitHub repo **before** you install it. repoguard looks for malware, credential and API-key theft,
phishing pages, data exfiltration, hidden or obfuscated code, dangerous install hooks, malicious AI-agent
configs (`CLAUDE.md`, `.mcp.json`, Claude/Cursor hooks), typosquatted dependencies, leaked secrets and
repo-reputation red flags. It gives a verdict, **SAFE / CAUTION / DANGEROUS / BLOCK**, with plain reasons.

- **Static only.** Nothing from the scanned repo is ever installed, built or run.
- **No API key needed.** Pure Python standard library, no dependencies, no LLM calls.
- 23 detectors, 18 correlation rules (attack chains like "reads ~/.ssh + sends to a Discord webhook").

There are two ways to use it. Pick one.

---

## Option 1: install the scanner + Claude Code agent (recommended)

Needs Python 3.12+ and git.

```bash
git clone https://github.com/JohnNasr/repoguard.git
cd repoguard
python repoguard-cli.py install-agent     # Windows: py repoguard-cli.py install-agent
```

This copies the agent into `~/.claude/agents/repoguard.md`, pointed at this folder. Open a **new** Claude Code
session and say:

> use the repoguard agent to check https://github.com/owner/repo

Claude runs the scanner, reads the flagged lines to confirm them, and answers with a verdict.
If you move the folder later, run `install-agent` again.

You can also run the scanner on its own:

```bash
python repoguard-cli.py scan owner/repo              # GitHub shorthand
python repoguard-cli.py scan https://github.com/owner/repo --history   # also scan the last 300 commits
python repoguard-cli.py scan ./some/local/folder
python repoguard-cli.py scan owner/repo --format json   # also: markdown, sarif
python repoguard-cli.py rules                        # list every rule
python repoguard-cli.py explain COR001               # explain one rule
python repoguard-cli.py clean                        # delete temp clones
```

Exit codes: `0` below the `--fail-on` level (default `dangerous`); at or above it `1` CAUTION, `2` DANGEROUS,
`3` BLOCK; `4` bad URL or clone failed; `5` internal error.

## Option 2: just copy a prompt (no install)

Don't want to install anything? Use [`prompt/repoguard-prompt.md`](prompt/repoguard-prompt.md).

- **Claude Code:** save it as `~/.claude/agents/repoguard.md`, then say "use the repoguard agent to check <url>".
- **Any other AI assistant with shell access:** paste the whole file as your message, then add the repo URL
  at the end.

The prompt makes the AI do the same checks by hand (safe clone with hooks off, then targeted searches).
It is slower and less thorough than Option 1, because it has no 23 tuned detectors, no scoring and no
correlation engine, but it works anywhere.

---

## What it checks

| Area | Examples |
|---|---|
| Install-time execution | npm `postinstall`, `setup.py` cmdclass, Makefiles, devcontainer, git hooks |
| Credential theft | `~/.ssh`, `~/.aws/credentials`, browser password stores, crypto wallets, `process.env` dumps |
| Exfiltration | Discord/Telegram webhooks, paste sites, tunnels, raw-IP URLs, DNS exfil |
| Malware | reverse shells, download-and-run, persistence, crypto miners, ransomware patterns |
| Obfuscation | base64/hex blobs that get executed, packed JS, invisible Unicode, bidi tricks |
| AI-agent attacks | prompt injection in `CLAUDE.md`/`AGENTS.md`, hostile `.mcp.json`, Claude/Cursor hooks |
| Phishing | fake login or "paste your API key" pages that post to a webhook |
| Dependencies | typosquats, known-malicious packages, git/URL dependencies |
| CI/CD | `pull_request_target` abuse, secrets sent to third parties, unpinned actions |
| Secrets | 16 secret rules (Anthropic, OpenAI, AWS, GitHub, Stripe, private keys, `.env`, ...) |
| Repo tricks | hostile `.git` config, symlinks out of the repo, case collisions, huge files |
| Reputation | repo age, stars, archived/fork status, lookalike names (GitHub API, optional) |

Full list: [`docs/RULES_CATALOG.md`](docs/RULES_CATALOG.md).

## How safe is the scan itself?

- git runs with hooks, filters, submodules, LFS and non-https protocols disabled, in a throwaway temp folder.
- Every subprocess has a timeout and an output cap. Big files, deep trees and slow regexes are bounded.
- Secrets found are masked in all output.

## Scanning repoguard with itself

It scores **BLOCK**. That is expected: the source and tests are full of the malware, phishing and
credential-theft patterns it looks for (like an antivirus signature file). A scanned repo can never silence
repoguard: in-repo ignore files are reported and ignored. Review the code yourself, or use Option 2.

## Limits

Static analysis cannot prove a repo is harmless. A SAFE verdict means nothing known-bad was found, not that
the code is trustworthy. For anything sensitive, still run it in a VM or container first.

## Development

```bash
python -m pip install pytest
python -m pytest -q
```

## License

MIT
