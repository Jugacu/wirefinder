# wirefinder — desktop GUI

The Tauri + React front end for wirefinder. It talks to `wirefinderd` over the
Unix socket via Tauri commands (`src-tauri/src/lib.rs` → `wirefinder-proto`), shows
the first-run onboarding wizard, and is the day-to-day way to switch servers.

See [`../README.md`](../README.md) for the whole product and architecture.

## Dev

```sh
pnpm install
pnpm tauri dev      # needs wirefinderd running (see ../README.md)

pnpm build          # tsc + vite build (frontend only)
pnpm tauri build    # full desktop bundle
```

The GUI is its own Tauri/Cargo build and is intentionally excluded from the Rust
workspace (`../Cargo.toml`).

## Layout

- `src/api.ts` — typed wrappers over the Tauri commands; mirrors `wirefinder-proto`.
- `src/App.tsx` — routes between loading / offline / onboarding / dashboard.
- `src/components/` — `Onboarding`, `Dashboard`, `ServerForm`, `CopyField`.
- `src/App.css` — the design system (dark, single accent colour).
