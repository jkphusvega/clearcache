# ClearCache

Windows disk cleanup tool: finds large folders, grades them by rules (and later AI), and moves only what you pick into a quarantine. Full spec: [SPEC.md](SPEC.md).

## Run (dev)

Prerequisites: Rust (MSVC toolchain), Visual Studio C++ Build Tools, Node.js, WebView2.

```
npm install
npm run tauri dev
```

## Status

- M1: app shell with title and empty folder table.
