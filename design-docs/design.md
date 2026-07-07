# lib-agent-browsercookies — design

Records *what* this module owns, *why* it exists, and the per-platform facts and
gotchas that must not be rediscovered — so the extraction from the two existing
implementations, and any later change, don't relitigate them.

## Origin

Two CLIs in the family need to read a credential cookie out of a locally
installed browser or desktop app: `agent-slack` (Slack's `d` / `xoxd` cookie)
and `agent-notion` (Notion's `token_v2`). Each grew its own `internal/auth`
cookie-extraction code — the same hard, security-sensitive, cross-platform
machinery, written twice and already **diverged**:

- `agent-slack` discovers Firefox profiles via `profiles.ini` and an explicit
  `profilesSubdir` flag (the mature approach);
- `agent-notion` scanned profile directories by name and, on macOS, looked in
  the wrong place entirely — a bug that shipped and had to be patched in one
  repo while the other was already correct.

Two copies of AES-GCM-decrypting a browser cookie store is exactly how subtle
security bugs and silent drift both happen. This module is the single home for
the mechanism; the CLIs depend on it and delete their copies. It stays free of
other family dependencies — reading a cookie must not pull in a CLI framework
or an MCP server.

## Mechanism vs policy

The seam that makes this a clean library: the **mechanism** is identical across
services; only a small **policy** differs.

### Mechanism (this module owns)

- **Store location, per OS.** Chromium keeps profiles under a `User Data`
  segment on Windows but not macOS/Linux — *except* Arc, which uses `User Data`
  everywhere. Firefox nests profiles under `Profiles/` on macOS and Windows but
  keeps them flat on Linux. Chromium uses `%LOCALAPPDATA%` on Windows; Firefox
  and Electron apps use `%APPDATA%` (Roaming). Electron apps (Notion Desktop,
  Slack Desktop) store cookies in per-app partition dirs.
- **Reading a locked SQLite.** Browsers hold `Cookies` / `cookies.sqlite` open;
  snapshot to a temp copy before reading. Use a pure-Go SQLite driver
  (`modernc.org/sqlite`) — the family ships static, cgo-free binaries.
- **Chromium decryption.** macOS/Linux: `v10`/`v11` values are AES-128-CBC with
  a PBKDF2-HMAC-SHA1(password, "saltysalt") key and a 16-space IV. Windows:
  AES-256-GCM with a DPAPI-unwrapped key read from `Local State`
  (`os_crypt.encrypted_key`, `DPAPI`/`APPB` prefixes; Chrome 127+ app-bound
  keys are a distinct, currently-unsupported case). Chromium meta-version ≥ 24
  prepends a 32-byte SHA-256(host) hash to the decrypted plaintext — strip it.
- **Safe Storage password.** macOS Keychain (`security`), Linux `secret-tool`,
  Windows DPAPI. Inject this behind a seam so tests never touch the real store.
- **Firefox / Gecko.** Parse `profiles.ini` (canonical) *and* scan the profile
  dir; honor the Default marker; read plaintext `moz_cookies`.
- **Safari.** Parse `Cookies.binarycookies` (macOS; needs Full Disk Access).

### Policy (the caller injects)

- **Which host(s) and cookie name.** A service may span domains — Notion serves
  the session on both `www.notion.so` (legacy) and `app.notion.com` (current;
  the Desktop app uses it exclusively). Matching only one silently misses the
  token on the other.
- **Verbatim vs decode.** This is the sharp edge. **Browsers transmit cookie
  values byte-for-byte** — there is no percent-decoding in the cookie protocol.
  Notion's `token_v2` embeds a percent-encoded prefix (`v03%3A…`) that is *part
  of the value*; URL-decoding it to `v03:…` produces a token the server rejects
  with 401. The safe default is **verbatim**. Any decoding is a per-service
  opt-in (Slack historically decoded its `d` cookie; if it works there it is a
  service quirk, not the general rule).

## Gotchas (learned the hard way)

- **Send the value verbatim.** See above. The default must be no-decode.
- **Notion uses two domains.** `notion.so` *and* `notion.com`. A `%notion.so`
  filter misses the Desktop app entirely.
- **macOS/Windows Firefox nest under `Profiles/`.** Linux is flat. Zen (a
  Firefox fork) mirrors this and uses title-cased, parenthesized profile dir
  names (`<hash>.Default (release)`), unlike Firefox's `<hash>.default-release`.
- **Chromium meta-version ≥ 24** prepends the 32-byte host hash — strip it
  before returning the value.
- **getSpaces-style validation is the consumer's job**, not this module's — but
  note APIs evolve (Notion's getSpaces began returning a `__version__` number
  among its record tables). Keep validation tolerant on the consumer side.
- **Never touch the real keychain in tests.** The Safe Storage password lookup
  must be a swappable seam.

## API direction (not yet stable)

The intended shape: the caller describes the **policy** (target browsers/app,
host predicate, cookie name, decode mode) and the module returns the extracted
value plus provenance (which store/profile it came from). The public surface is
being shaped by lifting the two existing implementations — starting from
`agent-slack`'s (the more mature Firefox discovery) and folding Notion's
domain/verbatim needs in as policy — so it is left unfrozen until both consumers
have migrated onto it.

## Port plan

1. Extract the mechanism here (Chromium decrypt, SQLite snapshot, Safe Storage
   seam, Gecko `profiles.ini` discovery, Safari binarycookies), with tests
   using fixture DBs and a stubbed password seam — never the real store.
2. Design the policy-injection surface; add Notion's two-domain match and Zen
   support as policy/registry entries.
3. Migrate `agent-slack` and `agent-notion` onto the module; delete their
   copies; re-release both.
