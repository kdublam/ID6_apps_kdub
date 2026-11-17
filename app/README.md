# ID6 Installer (preview)

Tauri 2 app (Rust core, TypeScript UI). This version only runs the read-only compatibility check from the AgentReadMe. Installing is not implemented yet.

SSH unlock is out of scope: unlock the head unit first with a tool such as Bavarian SSH Client.

## Develop

Requires Node and Rust (`rustup`).

    npm install
    npm run tauri dev
    cargo test --manifest-path src-tauri/Cargo.toml

Regenerate `src-tauri/profiles.json` after editing `source/docs/COMPATIBILITY.md`:

    python3 scripts/gen_profiles.py
