// Package browsercookies reads a single credential cookie out of a local,
// on-disk cookie store — a Chromium-family browser, Firefox/Gecko, Safari, or
// an Electron desktop app that embeds one — cross-platform, decrypting the
// value where the store encrypts it.
//
// It is the shared browser/desktop cookie-extraction primitive for the agent-*
// family. Both agent-notion (Notion's token_v2) and agent-slack (Slack's d
// cookie) need the same hard, security-sensitive, per-OS mechanism, and today
// each carries its own copy — which is how a fix landing in one and not the
// other happens. This module owns that mechanism once.
//
// # Mechanism vs policy
//
// The module owns the mechanism — everything that is the same regardless of
// which service's cookie you want:
//
//   - locating a browser/app cookie store per OS (Chromium "User Data" vs
//     macOS/Windows "Profiles" nesting vs flat Linux, Electron partitions);
//   - reading a locked Cookies SQLite by snapshotting it to a temp copy;
//   - Chromium decryption — macOS/Linux AES-128-CBC (PBKDF2 + "saltysalt") and
//     Windows AES-256-GCM (DPAPI-wrapped key from Local State), including the
//     meta-version >= 24 SHA-256(host) plaintext prefix;
//   - reading the Safe Storage password (macOS Keychain / Linux secret-tool /
//     Windows DPAPI);
//   - Firefox profile discovery (profiles.ini + the Profiles subdirectory) and
//     the plaintext moz_cookies read;
//   - the Safari Cookies.binarycookies parser.
//
// The caller injects the policy — the small set of decisions that are specific
// to the service whose cookie is wanted:
//
//   - which host(s) and cookie name to match;
//   - whether the value is sent verbatim (the default; browsers transmit cookie
//     values byte-for-byte, so a percent-encoded value like "v03%3A…" must NOT
//     be URL-decoded) or needs decoding for that particular service.
//
// The API is not yet stable; it is being shaped by extracting the existing
// implementations from agent-notion and agent-slack. The module stays free of
// other family dependencies.
package browsercookies
