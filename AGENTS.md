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

`tpm2-autoenrolld check-config [--config=PATH]` validates a config and exits, touching no device, TPM or socket. It is stricter than the daemon: any volume the daemon would drop, or a file with no volumes at all, exits non-zero. `nix/module.nix` runs it over the file it generates, and `nix/configcheck.nix` (`nix build .#checks.x86_64-linux.config-check`) is what holds it to that.

`tpm2-autoenrolld clear-sockets [--config=PATH] [--socket-dir=PATH]` unlinks the sockets the daemon would have bound for that config and exits. `sockets::clear` only ever removes sockets, so it cannot destroy a real key file sharing the directory. The module wires it up as `ExecStopPost=`; see the socket-lifetime note below.

## Architecture

The binary is `tpm2-autoenrolld`, a single-threaded daemon. It hooks into systemd-cryptsetup's key-discovery path: for each volume, systemd-cryptsetup connects to `/run/cryptsetup-keys.d/<volume>.key` if that path is a socket. The daemon binds one such socket per volume in its JSON config (`config.rs`; missing or unparseable means exit non-zero). The config is also the only source of the PCR selection and bank it enrolls with: the same fields in the LUKS2 header are unauthenticated (`cryptsetup token import` needs no key), so they are only ever compared against the config. It sends `READY=1` (`notify.rs`) only once every socket is bound.

On each connection, the peer's abstract AF_UNIX bind name (`bindname.rs`) shows which phase of systemd-cryptsetup's unlock loop is asking:
- **TPM2/FIDO2/PKCS#11 phase**: close with zero bytes. systemd then falls through to the LUKS2 header token and a normal TPM2 unlock goes ahead untouched.
- **Plain phase** (every token has failed): first `peer.rs` checks the connecting process is uid 0 and inside `systemd-cryptsetup@<volume>.service` (by cgroup, pinned with `SO_PEERPIDFD`), since any process can bind any name. Then `main::serve_passphrase` does the following, all before replying:
  1. `acquire`: tries passphrases cached earlier this boot (`cache.rs`), then prompts via `systemd-ask-password` (`askpw.rs`). Every candidate is checked against the device with `cryptsetup` (`luks.rs`) before it is trusted.
  2. `maybe_reenroll`: opens the TPM (`tpm2.rs`, raw TPM2 wire protocol over `/dev/tpmrm0`), reads the `systemd-tpm2` token from the header (`token.rs`), then runs the `preflight.rs` checks, one of which refuses when the header's PCR selection or bank differs from the config. The last of those is `drift.rs`, which compares the header's policy hash with a trial-session digest of the current PCRs. Next it asks for consent (`consent.rs`: Yes/Always/No, remembered per PCR state for this daemon's lifetime only), then runs `systemd-cryptenroll --wipe-slot=tpm2` (`enroll.rs`), and finally verifies the result with a token-only unseal, falling back to a drift comparison.
  3. `reply`: writes the passphrase verbatim.

Connections are handled one at a time. This is deliberate: parallel prompts would interleave on the console, and serial handling is what lets the passphrase cache help the next volume. The cost is that one stall blocks every volume behind it, so every blocking step has a deadline: TPM responses (`tpm2.rs`), and every subprocess, which runs through `child::run` and is killed past its budget.

The daemon exits once every configured volume is open (`dm.rs`) or has been answered in the plain phase, or after 5 minutes with no connection, so the passphrase cache does not outlive the unlock. The `Wants=` drop-in starts it again for any later `systemd-cryptsetup@` start, with an empty cache and no remembered consent. On that exit, and on SIGTERM, the daemon unlinks its sockets.

Removing them matters more than "found by stage 2" suggests. `/run` survives switch-root, and a socket with no listener behind it is not a fall back to stock behaviour: systemd-cryptsetup's `find_key_file()` (`src/cryptsetup/cryptsetup-keyfile.c`) passes anything but `ENOENT` and `E2BIG` up as a fatal error, so the refused connect fails the volume outright and nobody is even prompted. Two things keep that from happening. `main::terminating()` is consulted before every multi-second step of serving a connection — each cache trial, each prompt, the consent prompt, the enrollment — because one connection's own budget runs to minutes and spending it after a stop was asked for is what reaches the unit's stop timeout and earns a SIGKILL. And the module's `ExecStopPost=` runs `clear-sockets` however the main process ended, which covers a stop-timeout SIGKILL that gets through anyway: systemd reaches `SERVICE_STOP_POST` only once the SIGKILL phase is over. The one thing it cannot cover is the whole cgroup being killed at once (`systemctl kill` without `--kill-whom=main`, or the OOM killer), because the control process lives in that cgroup too — which is why the `terminating()` checks matter rather than being a nicety. `socket-core` assertion 9 is the test.

### Invariants to preserve

- **Fail closed means decline.** Any path that cannot make sense of a request drops the connection without writing anything, so the volume unlocks exactly as it would without this tool.
- **Never touch the passphrase slot.** Every re-enrollment failure has to stay recoverable by passphrase.
- **Preflight refuses unless every check passes.** It does not act unless something looks wrong.
- **The header is never a source of policy.** Anything enrolled with (PCRs, bank) comes from the config; the header's values are compared, not used.
- **Consent is mandatory** and never persisted across boots or made configurable. See the `consent.rs` header for the evil-maid reasoning.
- **The device is resolved once.** `serve_passphrase` opens the configured path once (`device.rs`) and every subprocess gets `/proc/self/fd/N` for that descriptor, so a `/dev/disk/by-*` symlink changing mid-flow cannot split validation and enrollment across disks. Prompts still show the configured path.
- **Key material** lives only in `secret::Secret` (zeroized, never printed by `Debug`). It reaches child processes through a memfd (`memfd.rs`), never through argv or the environment.

### Initrd constraints

The binary is meant to go into the initrd, so closure size shapes the code:
- No libcryptsetup or tpm2-tss (both would also rule out a static musl build). The daemon shells out to `cryptsetup`, `systemd-cryptenroll`, and `systemd-ask-password`, and hand-rolls the TPM commands, sd_notify, and logging (`log.rs`, which writes syslog-prefixed lines to stderr).
- `serde_json` is used with `default-features = false` and no serde_derive; JSON is walked as `Value`.
- The Nix package is deliberately **not** wrapped with a PATH. `nix/module.nix` supplies PATH for each stage and names the three binaries one by one in `boot.initrd.systemd.storePaths`, so a whole second systemd is not copied in. Don't add `wrapProgram`.

### NixOS module (`nix/module.nix`)

Volumes are listed per stage in `services.tpm2-autoenroll.stages.<initrd|system>.volumes.<name> = { device; pcrs; tpm2_device ? "auto"; pcr_bank ? "sha256"; }`. The options are named after the JSON keys and the volume submodule is freeform (`pkgs.formats.json`), so a stage's `volumes` attrset is written out as the config's `volumes` object verbatim and an undeclared key reaches the daemon untouched. Nix therefore cannot judge the schema, so the generated file is passed through `tpm2-autoenrolld check-config` at build time and a key the daemon would reject fails the build — except on a cross build, where the binary cannot run on the builder and the check is skipped. For each stage that has volumes it installs:
- a `Type=notify`, `DefaultDependencies=no` service ordered before `cryptsetup-pre.target`, which in the initrd also conflicts with `initrd-switch-root.target`;
- a drop-in on the `systemd-cryptsetup@.service` template adding `Wants=`/`After=` on the daemon;
- a config at `/etc/tpm2-autoenroll/config.json` holding only that stage's volumes (`boot.initrd.systemd.contents` or `environment.etc`).

The service is sandboxed (`NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX AF_ALG AF_NETLINK`, and more in stage 2 only, since no test boots the initrd). It needs block devices and the TPM, so never add `PrivateDevices`, `DevicePolicy` or `ProtectClock` (which implies a `DeviceAllow=` list). The VM coverage for these directives is `moduletest.nix`; `vmtest.nix` uses a hand-written unit.

`Wants=` is used rather than `Requires=` so that a daemon which fails to start costs the feature, not the boot. Initrd volumes assert that `boot.initrd.systemd.enable` and `boot.initrd.systemd.tpm2.enable` are set, and that `boot.initrd.luks.devices.<name>` exists, has no `keyFile`, and has `tpm2-device=` in `crypttabExtraOpts`.

## Conventions

- Some comments and tests refer to `DESIGN.md` sections. That file was deleted in `c1e91cb`; read it with `git show c1e91cb^:DESIGN.md`.
- Commit subjects are prefixed with a component: `daemon:`, `module:`, `test:`, `package:`, `config:`, `docs:`.
