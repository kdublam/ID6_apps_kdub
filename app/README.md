# ID6 Installer (preview)

Tauri 2 app (Rust core, TypeScript UI). It runs the compatibility check, installs and uninstalls the app packages from `../packages`, and backs up and restores them.

## Install, backup and restore

- Installing re-runs the compatibility check and refuses unless the head unit is a supported match.
- Files are staged outside `Plugins` and read back byte for byte. Package `SHA256SUMS` are verified first, and connector id conflicts with other installed apps are refused.
- Before anything changes, the affected folders (plus the legacy `ExhaustFlap` when installing MHD+) are copied to `/var/opt/hmi/data/ID5/ID6Installer/backups/<id>` on the head unit and to the app data folder on this computer. Both copies are verified.
- Publishing is one remote script under an install lock that rolls back on any failure.
- Backups & restore puts the apps listed in a backup back to their backed-up state (including removing apps that were not installed then). If the head unit copy is gone it re-uploads from the local copy. Folders replaced by a restore are kept under `ID6Installer/restored-*`.
- Settings stored outside the plugin folders are not backed up.

SSH unlock is out of scope: unlock the head unit first with a tool such as Bavarian SSH Client.

## Develop

Requires Node and Rust (`rustup`).

    npm install
    npm run tauri dev
    cargo test --manifest-path src-tauri/Cargo.toml

Regenerate `src-tauri/profiles.json` after editing `source/docs/COMPATIBILITY.md`:

    python3 scripts/gen_profiles.py
