# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## AI policy (from README.md)

AI must not write, wholly or partially:
- Pull request titles, descriptions, or comments, or any other direct communication with humans.
- Documentation files (README.md and other markdown docs). Code comments are fine, and so are AI-only docs like this file.

If a task calls for either, draft nothing and tell the user it is theirs to write.

## Commands

The toolchain comes from the flake dev shell (cargo, rustc, rustfmt, clippy, cryptsetup, tpm2-tools):

```sh
nix develop -c cargo build
nix develop -c cargo test                              # unit tests, all in-module #[cfg(test)]
nix develop -c cargo test token::tests::rejects_a_token_without_a_policy_hash   # a single test
nix develop -c cargo clippy
nix build                                              # the package (tpm2-autoenrolld)
nix flake check                                        # package + both NixOS VM tests
nix build .#checks.x86_64-linux.socket-core            # nix/vmtest.nix: daemon behaviour, hand-written unit
nix build .#checks.x86_64-linux.module                 # nix/moduletest.nix: everything from the NixOS module
```

The VM tests use swtpm and are x86_64-linux only. `socket-core` assertion 1 (a healthy TPM2 unlock stays silent with the socket installed) is the regression test to run first against a new systemd.

`rustfmt.toml` sets `hard_tabs = true`.

The daemon can be run by hand with `--config=` and `--socket-dir=` overrides (defaults: `/etc/tpm2-autoenroll/config.json`, `/run/cryptsetup-keys.d`).

## Architecture

The binary is `tpm2-autoenrolld`, a single-threaded daemon. It hooks into systemd-cryptsetup's key-discovery path: for each volume, systemd-cryptsetup connects to `/run/cryptsetup-keys.d/<volume>.key` if that path is a socket. The daemon binds one such socket per volume in its JSON config (`config.rs`; missing or unparseable means exit non-zero). The config is also the only source of the PCR selection and bank it enrolls with: the same fields in the LUKS2 header are unauthenticated (`cryptsetup token import` needs no key), so they are only ever compared against the config. It sends `READY=1` (`notify.rs`) only once every socket is bound.

On each connection, the peer's abstract AF_UNIX bind name (`bindname.rs`) shows which phase of systemd-cryptsetup's unlock loop is asking:
- **TPM2/FIDO2/PKCS#11 phase**: close with zero bytes. systemd then falls through to the LUKS2 header token and a normal TPM2 unlock goes ahead untouched.
- **Plain phase** (every token has failed): `main::serve_passphrase` does the following, all before replying:
  1. `acquire`: tries passphrases cached earlier this boot (`cache.rs`), then prompts via `systemd-ask-password` (`askpw.rs`). Every candidate is checked against the device with `cryptsetup` (`luks.rs`) before it is trusted.
  2. `maybe_reenroll`: opens the TPM (`tpm2.rs`, raw TPM2 wire protocol over `/dev/tpmrm0`), reads the `systemd-tpm2` token from the header (`token.rs`), then runs the `preflight.rs` checks, one of which refuses when the header's PCR selection or bank differs from the config. The last of those is `drift.rs`, which compares the header's policy hash with a trial-session digest of the current PCRs. Next it asks for consent (`consent.rs`: Yes/Always/No, remembered per PCR state for this daemon's lifetime only), then runs `systemd-cryptenroll --wipe-slot=tpm2` (`enroll.rs`), and finally verifies the result with a token-only unseal, falling back to a drift comparison.
  3. `reply`: writes the passphrase verbatim.

Connections are handled one at a time. This is deliberate: parallel prompts would interleave on the console, and serial handling is what lets the passphrase cache help the next volume.

On SIGTERM the daemon unlinks its sockets. `/run` survives switch-root, so a leftover socket would be found by stage 2.

### Invariants to preserve

- **Fail closed means decline.** Any path that cannot make sense of a request drops the connection without writing anything, so the volume unlocks exactly as it would without this tool.
- **Never touch the passphrase slot.** Every re-enrollment failure has to stay recoverable by passphrase.
- **Preflight refuses unless every check passes.** It does not act unless something looks wrong.
- **The header is never a source of policy.** Anything enrolled with (PCRs, bank) comes from the config; the header's values are compared, not used.
- **Consent is mandatory** and never persisted across boots or made configurable. See the `consent.rs` header for the evil-maid reasoning.
- **Key material** lives only in `secret::Secret` (zeroized, never printed by `Debug`). It reaches child processes through a memfd (`memfd.rs`), never through argv or the environment.

### Initrd constraints

The binary is meant to go into the initrd, so closure size shapes the code:
- No libcryptsetup or tpm2-tss (both would also rule out a static musl build). The daemon shells out to `cryptsetup`, `systemd-cryptenroll`, and `systemd-ask-password`, and hand-rolls the TPM commands, sd_notify, and logging (`log.rs`, which writes syslog-prefixed lines to stderr).
- `serde_json` is used with `default-features = false` and no serde_derive; JSON is walked as `Value`.
- The Nix package is deliberately **not** wrapped with a PATH. `nix/module.nix` supplies PATH for each stage and names the three binaries one by one in `boot.initrd.systemd.storePaths`, so a whole second systemd is not copied in. Don't add `wrapProgram`.

### NixOS module (`nix/module.nix`)

Volumes are listed in `services.tpm2-autoenroll.volumes.<name> = { device; tpm2Device ? "auto"; pcrs; pcrBank ? "sha256"; stage ? "initrd"; }` (`stage` is `initrd` or `system`). The Nix options are camelCase, the JSON keys snake_case. For each stage that has volumes it installs:
- a `Type=notify`, `DefaultDependencies=no` service ordered before `cryptsetup-pre.target`, which in the initrd also conflicts with `initrd-switch-root.target`;
- a drop-in on the `systemd-cryptsetup@.service` template adding `Wants=`/`After=` on the daemon;
- a config at `/etc/tpm2-autoenroll/config.json` holding only that stage's volumes (`boot.initrd.systemd.contents` or `environment.etc`).

`Wants=` is used rather than `Requires=` so that a daemon which fails to start costs the feature, not the boot. Initrd volumes assert that `boot.initrd.systemd.enable` and `boot.initrd.systemd.tpm2.enable` are set, and that `boot.initrd.luks.devices.<name>` exists, has no `keyFile`, and has `tpm2-device=` in `crypttabExtraOpts`.

## Conventions

- Some comments and tests refer to `DESIGN.md` sections. That file was deleted in `c1e91cb`; read it with `git show c1e91cb^:DESIGN.md`.
- Commit subjects are prefixed with a component: `daemon:`, `module:`, `test:`, `package:`, `config:`, `docs:`.
