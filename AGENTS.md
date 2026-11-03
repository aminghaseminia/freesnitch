# AGENTS.md

Guidance for AI agents (and humans) working on FreeSnitch. Read the "Build" and
"Invariants" sections before changing anything: several failure modes here are
silent at build time and fatal at launch.

FreeSnitch is an open-source application firewall for macOS: a SwiftUI menu-bar
app, a privileged root helper, an optional Network System Extension, and a CLI.
Swift 5.10, macOS 13+ deployment target, MIT licensed.

---

## Build

A generated project is the source of truth, not the checked-in one: `*.xcodeproj/`
is gitignored and produced by XcodeGen from `project.yml`.

```sh
cd ~/Projects/freesnitch
xcodegen generate --spec project.yml
```

Full Xcode is required (`xcodebuild` does not run on Command Line Tools alone).
If `xcodebuild -version` reports "requires Xcode", either run
`sudo xcode-select -s /Applications/Xcode.app/Contents/Developer` once, or export
`DEVELOPER_DIR` in every shell as below. The export needs no admin rights.

This machine has no Developer ID certificate, so sign nothing. This is the exact
unsigned recipe CI uses:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer   # if xcode-select is not set

xcodebuild \
  -project FreeSnitch.xcodeproj \
  -scheme FreeSnitch \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -derivedDataPath build \
  CODE_SIGN_IDENTITY=- \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
  PROVISIONING_PROFILE_SPECIFIER='' \
  build
```

The app lands at `build/Build/Products/Release/FreeSnitch.app`:

```sh
open build/Build/Products/Release/FreeSnitch.app
```

### Rebuild loop

| You changed | Do |
|---|---|
| Swift files under `Sources/` | `xcodebuild` again (above). No regen needed. |
| `project.yml`, added/removed a file, Info.plist, entitlements | `xcodegen generate --spec project.yml`, then build |
| Nothing, want a clean slate | add `clean` before `build` |

Never hand-edit `FreeSnitch.xcodeproj`; it is regenerated and discarded.

### What a local unsigned build can and cannot do

`project.yml` builds the **monitor** flavour on purpose: it omits the Network
System Extension so the project compiles without Apple-issued provisioning
profiles. Expect these limits locally, they are not bugs:

- The root helper will not register, so no real filtering and no persistent
  rules; the GUI uses in-memory state.
- No per-process filtering (that lives in `Sources/NetExt`).
- The `.app` is unsigned, so Gatekeeper and app-group access behave differently
  than a release build.

The **firewall** flavour is `project-netext.yml`. Do not build it unless you
have the two Developer ID profiles described in `docs/NETWORK-EXTENSION.md`;
without them the restricted entitlements cause AMFI to refuse to start the
process, and `xcodebuild` fails outright.

---

## Repo map

| Path | Contents |
|---|---|
| `Sources/GUI` | SwiftUI app. `App/` (entry point, `HelperClient`, window/menubar/Sparkle wiring), `ViewModels/` (`AppState` drives the UI), `Views/` (one file per screen/pane) |
| `Sources/Helper` | Root launchd daemon: `PFManager` (writes `/etc/pf.anchors/puresnitch`, runs `pfctl`), `DNSProxy` (DNS on 127.0.0.1:53 + DoH upstream), `NetMonitor` (parses `nettop`/`lsof`), `BlocklistManager`, `RuleStore` (SQLite), `HelperService` (XPC listener) |
| `Sources/Shared` | Compiled into every target: `HelperProtocol` (XPC contract), `Models`, `RuleStore`, `RuleMatcher`, `WireCodec`, `RuleTransport`, `Profile*`, `IPGeo`, `Logger` |
| `Sources/NetExt` | `NEFilterDataProvider` content filter for the firewall flavour |
| `Sources/CLI` | `freesnitch` CLI, shipped at `Contents/Helpers/freesnitch`. Keep the binary inside the bundle: its signature and identifier are part of the XPC trust boundary. **It is not a trusted XPC peer** (see invariants): privileged commands now direct the user to the app |
| `Scripts/` | `test_*.sh` harnesses, `audit_firewall_safety.sh`, `release.sh`, `screenshots.sh`, `make_icon.sh`, uninstallers |
| `docs/` | `architecture.md`, `CLI.md`, `NETWORK-EXTENSION.md`, `ci-and-releases.md`, GitHub Pages site (`index.html`) |

Three processes: GUI (user) → helper (root, XPC over a Mach service) → kernel
(`pfctl`, `nettop`, `lsof`). `notifyAlert` is the call that raises an
Allow/Deny sheet in Alert mode. See `docs/architecture.md` for the diagrams.

---

## Invariants that quietly break things

1. **Explicit `PRODUCT_NAME` is mandatory.** Xcode 27 no longer falls back to
   the target name; without it the Swift module name resolves to `""` and the
   build dies with `Module name "" is not a valid identifier`.
2. **The system extension bundle filename must equal its bundle identifier**
   (`io.isaaclins.freesnitch.netext`). `sysextd` matches by filename, not by the
   identifier in `Info.plist`. Rename it and activation fails with
   "Extension not found in App bundle".
3. **Never add restricted entitlements to `project.yml`.** `com.apple.developer.
   networking.networkextension` and `com.apple.developer.system-extension.
   install` require an embedded Apple profile. Without one the app is refused
   before `main()` runs, which looks to users like an app that will not open.
4. **Code signing identity and app group are hardcoded to team `BHAF4L4726`.**
   Any local build must override signing (see above); the app group
   `BHAF4L4726.io.isaaclins.freesnitch` will not resolve without that team.
5. **Fail-open behaviour is a security contract.** `Scripts/audit_firewall_safety.sh`
   statically checks that the extension and helper stay fail-open on error, that
   XPC peers are validated, and that the rule snapshot is consistent. It gates
   CI. Run it after touching `NetExt`, `HelperService`, `IPCConnection`,
   `XPCPeerValidator`, `RuleTransport`, or the pf/DNS policy path.
6. **The XPC/wire contract is shared.** Changing `HelperProtocol`, `Models`,
   `WireCodec`, or `RuleTransport` breaks GUI, helper, CLI and extension at
   once; change all of them in one commit.
7. **`LSUIElement` is true**: menu-bar app, no Dock icon. Do not add one.
8. **The helper runs as root.** Anything it reads from the GUI is untrusted
   input: validate paths, hosts and URLs (`PFHostValidator`,
   `DoHUpstreamValidator`, `ProfileValidation` exist for this).
9. **Never add the CLI (or another local binary) to the helper's peer
   allowlist.** `XPCPeerValidator.permittedPeerIdentifiers` is GUI-only on
   purpose: a world-executable, unauthenticated CLI as a trusted peer let any
   local process disable enforcement or replace the DoH upstream. For the same
   reason, code-signature exemptions need `anchor apple generic` plus the team
   check, never a bare `identifier` match.

---

## Tests

There is no XCTest target. Each `Scripts/test_*.sh` is a standalone harness that
compiles the *real* sources with `swiftc` and asserts in-process, so they catch
regressions the type checker cannot:

```sh
bash Scripts/test_pf_policy_sync.sh
bash Scripts/audit_firewall_safety.sh   # the release gate, runs anywhere
```

- 21 harnesses, one (`test_helper_identity.sh`) needs `sudo`.
- 16 hardcode `arm64-apple-macos13.0`; on Intel, change the target before
  running them.
- They are fast and independent: run the ones touching your area.

## Conventions

- No new dependencies without a load-bearing reason (SQLite via `import SQLite3`
  is fine).
- No emoji in code or commits.
- Comments explain *why*, not *what*; names carry the *what*.
- SwiftUI views split into small private computed properties. No mega-views.
- Warnings are not fatal (`SWIFT_TREAT_WARNINGS_AS_ERRORS: NO`), but keep your
  changed files clean.
- Everything user-facing is English today; strings are not yet `.strings`-extracted.

## Debugging

Logs are one subsystem:

```sh
log stream --predicate 'subsystem == "io.isaaclins.freesnitch"'
```

Demo data, no helper or extension needed (used by `Scripts/screenshots.sh`):

```sh
FREESNITCH_DEMO=1 open -n build/Build/Products/Release/FreeSnitch.app
```

Checking helper state by hand:

```sh
sudo lsof -nP -iUDP:53          # DNS proxy bound?
sudo pfctl -a puresnitch -s rules   # rules loaded?
```

## Releasing

`Scripts/release.sh` is the maintainer-only path: it bumps the version, builds
the firewall flavour from `project-netext.yml`, signs with a Developer ID,
notarizes, staples, writes the Sparkle appcast, then commits, tags and publishes.
It refuses to run from a dirty or unpushed `main`. Do not run it to test a
change; use `--dry-run` or `--validate-only`.

Bump `CFBundleShortVersionString` / `CFBundleVersion` in all three target
configs in `project.yml` when the version changes (the release script does this
for you). The README and `docs/index.html` also name the current version and
SHA-256 and are updated by hand after a release.
