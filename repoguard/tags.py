"""Shared tag vocabulary. Tags are the contract between detectors and the
correlation engine, so detectors must use these constants, never ad-hoc strings."""

READS_CREDENTIALS = "reads_credentials"  # touches ~/.ssh, ~/.aws, browser DBs, wallets, tokens
ENV_HARVEST = "env_harvest"  # dumps the whole environment
NETWORK_SEND = "network_send"  # sends data out (POST, webhook, socket send)
EXFIL_CHANNEL = "exfil_channel"  # known exfil endpoint: discord webhook, telegram bot, pastebin...
DOWNLOAD = "download"  # fetches remote content
EXEC_DYNAMIC = "exec_dynamic"  # eval/exec/Function/child_process/subprocess(shell)/iex
DECODE = "decode"  # base64/hex/charcode/zlib/marshal decoding
OBFUSCATED = "obfuscated"  # packers, encoded blobs, minified-in-source, high entropy
INSTALL_HOOK = "install_hook"  # runs on install/build (npm scripts, setup.py, build.rs...)
OPEN_HOOK = "open_hook"  # runs on open (VS Code tasks folderOpen, devcontainer, AI hooks)
PERSISTENCE = "persistence"  # autoruns, cron, launchd, systemd, startup folder
AV_TAMPER = "av_tamper"  # disables Defender/AV/firewall, UAC bypass
REVERSE_SHELL = "reverse_shell"
MINER = "miner"
PROCESS_INJECTION = "process_injection"
SURVEILLANCE = "surveillance"  # keylogger, screen capture, clipboard
ANTI_ANALYSIS = "anti_analysis"  # sandbox/VM/debugger checks, delays
PHISHING = "phishing"  # fake credential prompts / forms posting keys to third parties
AI_INSTRUCTION = "ai_instruction"  # text aimed at AI agents (prompt injection)
INVISIBLE_UNICODE = "invisible_unicode"
SECRET = "secret"  # committed credential (secret rules; reused by --history)
BINARY_EXEC = "binary_exec"  # committed executable / native code
DEPENDENCY_RISK = "dependency_risk"
TYPOSQUAT = "typosquat"
CI_RISK = "ci_risk"
FS_TRICK = "fs_trick"
EVASION = "evasion"  # tries to hide from scanners / reviewers
HYGIENE = "hygiene"  # harms the repo owner (leaked key, CVE), not the person installing; score-capped
NO_DAMPEN = "no_dampen"  # do not reduce score for test/doc/vendored location
BLOCK_TRIGGER = "block_trigger"  # forces verdict BLOCK regardless of score

ALL: frozenset[str] = frozenset(
    v for k, v in dict(globals()).items() if k.isupper() and isinstance(v, str)
)
