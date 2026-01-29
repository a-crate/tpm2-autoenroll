# tpm2-autoenroll design

Status: draft, pre-implementation
Target: systemd 260 (verified against 260.2 source)

## 1. Problem

TPM2-bound LUKS2 volumes unlock silently as long as the PCR values selected at
enrollment time still match. Any change to the measured boot chain -- a firmware
update, a kernel update, a change to the kernel command line, toggling Secure
Boot -- invalidates the sealed policy. The volume then falls back to a
passphrase prompt, and stays that way forever until the user manually runs
`systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto ...`.

In practice, users either do that dance after every update or give up on TPM2
binding. `tpm2-autoenroll` closes the loop: when a volume falls back to a
passphrase, re-bind it to the current PCR state at that moment, so the next boot
is silent again.

The invariant that makes this correct: **enroll at the point of unlock.** The
PCR values read at the moment we are consulted are, by construction, the values
that will be present the next time that same volume is unlocked at that same
point in boot. For a root volume that point is inside the initrd, which is why
the daemon has to run there -- enrolling afterwards from the booted system would
capture a PCR state (PCR 11 post-`leave-initrd`, PCR 12/13/15 extended by
userspace) that never recurs at the initrd's unlock time.

The invariant generalizes, though, and the daemon is deliberately stage-agnostic
(9.1): a data volume unlocked from the booted system captures its own stage's
PCR state, which is equally the correct state for it. Nothing in the design
special-cases the initrd; correctness follows from being invoked at the same
point where the unlock happens, wherever that is.

## 2. How systemd-cryptsetup actually unlocks

This section is the load-bearing part of the design. All references are to
systemd 260.2.

`verb_attach()` in `src/cryptsetup/cryptsetup.c` runs a retry loop
(`cryptsetup.c:2715`, default `arg_tries = 3`, `cryptsetup.c:87`). Each
iteration recomputes the token type and tries exactly one key source, in this
documented priority order (`cryptsetup.c:2724`):

1. A key acquired via PKCS#11, FIDO2, or TPM2
2. The configured key file (crypttab field 3) or the *discovered* key file
3. The empty password, if `try-empty-password` is set
4. Interactive passphrase prompt

On `-EAGAIN` from an attempt, the loop invalidates one source and continues
(`cryptsetup.c:2786`), in this order: TPM2, then FIDO2, then PKCS#11, then the
discovered key, then the configured key file, then collected passwords. So a
TPM2 failure demotes to the key file, and a key file failure demotes to the
prompt.

### 2.1 The socket key file protocol

crypttab(5) specifies that if a key file path refers to an AF_UNIX stream socket,
systemd-cryptsetup connects to it and reads the key from the connection. The
client binds its own end to an *abstract* socket name before connecting:

    NUL RANDOM "/cryptsetup/" VOLUME

for example `\0d7067f78d9827418/cryptsetup/myvol`. The listening service recovers
this with `getpeername(2)`, which is how a single listener can serve many
volumes. Constructed by `make_bindname()` at `cryptsetup.c:1373`.

The infix differs by what is being requested:

| infix                   | meaning                                    |
|-------------------------|--------------------------------------------|
| `/cryptsetup/`          | the actual passphrase / key                |
| `/cryptsetup-tpm2/`     | the *encrypted* TPM2 blob                  |
| `/cryptsetup-fido2-salt/` | the FIDO2 salt                           |
| `/cryptsetup-pkcs11/`   | the PKCS#11 encrypted key                  |

The infix is the signal we build the whole design around: it tells us which
phase of the unlock we are being consulted in.

### 2.2 Why crypttab field 3 cannot be used

A socket in crypttab field 3 *is* consulted at the right moments -- twice, with
both bindnames. Attempt 0 reaches us as `/cryptsetup-tpm2/<volume>`, and if TPM2
fails, attempt 1 reaches us as `/cryptsetup/<volume>`, because
`attach_luks_or_plain_or_bitlk_by_key_file()` builds its bindname with
`_TOKEN_TYPE_INVALID` (`cryptsetup.c:2302`). So the hook does exist there.

The problem is narrower and more stubborn: **we cannot decline attempt 0.** The
dispatch test in `attach_luks_or_plain_or_bitlk_by_tpm2()` is

    if (key_file || iovec_is_set(key_data))     /* cryptsetup.c:2044 */

With field 3 configured, `key_file` is a non-NULL path string no matter what
bytes we write back, so this branch is taken unconditionally. It calls
`acquire_tpm2_key()` with a hardcoded legacy PCR mask, `pcr_bank = UINT16_MAX`,
`primary_alg = 0`, and no salt or SRK, treating our reply as the encrypted blob.
The `else` branch -- the one that reads the real enrollment out of the LUKS2
header via `find_tpm2_auto_data()` -- is unreachable. Since modern
`systemd-cryptenroll` enrollments carry a salt and an SRK, the key-file branch
cannot unlock them at all, and no cross-attempt retry reaches the header: the
branch returns `-EAGAIN`, and the main loop responds by clearing
`arg_tpm2_device` outright (`cryptsetup.c:2786`).

A second route is closed off the same way: `cryptsetup.c:2692` gates the
libcryptsetup token-plugin path on `if (!key_file && use_token_plugins())`.

Net effect: crypttab field 3 plus `tpm2-device=` means the header token is never
consulted and the volume prompts on every boot.

crypttab(5) corroborates this from the other side. Its KEY ACQUISITION list
describes the TPM2 encrypted key as "stored on disk/removable media, acquired
via AF_UNIX, or stored in the LUKS2 JSON token metadata header" -- three
alternatives for one slot -- and notes that for these mechanisms the key
material source "is primarily configured in the third field", with keys.d and
the header as the other options. No fallback between them is promised. The
AF_UNIX KEY FILES section is explicit about intent: a distinct path component is
used "so that services providing key material know that the secret key was not
requested directly, but instead an encrypted key that will be decrypted via the
PKCS#11/FIDO2/TPM2 logic".

So the man page tells socket services in advance that a `/cryptsetup-tpm2/`
request wants a blob. What it does not state, and what comes from the source, is
that configuring field 3 makes that request unconditional.
### 2.3 The mechanism that does work

Leave crypttab's key file field empty and place the socket at

    /run/cryptsetup-keys.d/<volume>.key

When no key file is configured, `verb_attach()` sets `try_discover_key = true`
(`cryptsetup.c:2712`) and calls `discover_key()` (`cryptsetup.c:2562`) on each
iteration. `discover_key()` searches `/etc/cryptsetup-keys.d` then
`/run/cryptsetup-keys.d` via `find_key_file()`
(`src/cryptsetup/cryptsetup-keyfile.c`), which passes
`READ_FULL_FILE_CONNECT_SOCKET` and therefore connects to our socket -- and
crucially passes the *current iteration's* token type into `make_bindname()`.

This yields the sequence we need:

**Attempt 0.** `token_type == TOKEN_TPM2`. We are contacted as
`\0<rand>/cryptsetup-tpm2/<volume>`. We reply with **zero bytes** and close.
`find_key_file()` returns 1 with a zero-length iovec, so `key_data` is non-NULL
but `iovec_is_set()` is false (`src/fundamental/iovec-util-fundamental.h:43`
requires `iov_len > 0`). The `key_file || iovec_is_set(key_data)` test at
`cryptsetup.c:2044` is therefore false, and control falls into the normal
LUKS2-header TPM2 path. **Ordinary TPM2 unlocking is fully preserved.**

This is the whole reason for using discovery rather than field 3. Both routes
reach us at the same two moments; only this one lets us decline the first. Here
there is no `key_file` string forcing the branch -- only `key_data`, whose
emptiness we control by writing nothing. The distinction is a single `||` in
systemd, and the design rests on it.

**Attempt 1.** Reached only if TPM2 failed. The loop cleared `arg_tpm2_device`,
so `determine_token_type()` (`cryptsetup.c:2551`) now returns invalid and
`discover_key()` builds the bindname `\0<rand>/cryptsetup/<volume>`. That infix
is our cue: TPM2 has already failed for this volume. We prompt, re-enroll, and
return the passphrase, which `attach_luks_or_plain_or_bitlk_by_key_data()`
(`cryptsetup.c:2258`) feeds to `crypt_activate_by_passphrase()`.

**Attempt 2.** Reached only if our passphrase was wrong. `try_discover_key` is
now false, so systemd-cryptsetup prompts the user directly, exactly as it would
without us installed.

Two consequences worth designing around:

- We get **one** shot per volume before control reverts to stock behaviour. The
  daemon must therefore run its own retry loop for passphrase typos rather than
  returning a wrong passphrase and burning cryptsetup's remaining attempt.
- The reply bytes are used **verbatim** as the passphrase. No trailing newline.

## 3. Architecture

```
                 .-------------------------------------------.
                 |  systemd-cryptsetup@<vol>.service (initrd) |
                 '-------------------------------------------'
                        |  attempt 0             |  attempt 1
                        |  bindname              |  bindname
                        |  /cryptsetup-tpm2/vol  |  /cryptsetup/vol
                        v                        v
        /run/cryptsetup-keys.d/<vol>.key  (AF_UNIX stream, systemd .socket)
                        |
                        v
        .-------------------------------------------------.
        |  tpm2-autoenrolld  (Accept=no, one process,      |
        |                     N listening fds)             |
        |                                                  |
        |  reply empty  <--- tpm2 context                  |
        |                                                  |
        |  plain context:                                  |
        |    1. passphrase from cache, else ask-password   |
        |    2. validate against the volume                |
        |    3. TPM2 preflight                             |
        |    4. consent prompt (mandatory)                 |
        |    5. systemd-cryptenroll                        |
        |    6. verify, then reply with passphrase         |
        '-------------------------------------------------'
```

One process, one `.socket` unit with one `ListenStream=` per managed volume.
`Accept=no`, so all connections land on the single long-lived daemon and the
passphrase cache is shared across volumes. The listening fd identifies the
volume (`getsockname(2)` on the path); the peer name identifies the phase
(`getpeername(2)` on the abstract name).

### 3.1 Unit ordering

The socket must be listening before any `systemd-cryptsetup@.service` starts.
`cryptsetup-pre.target` is the anchor for that in both stages; the
`initrd-switch-root.target` lines below apply only to the initrd copy of the
unit and are omitted from the system-stage copy.

```
[Unit]
DefaultDependencies=no
Before=cryptsetup-pre.target
Conflicts=initrd-switch-root.target      # initrd stage only
Before=initrd-switch-root.target         # initrd stage only

[Socket]
ListenStream=/run/cryptsetup-keys.d/root.key
ListenStream=/run/cryptsetup-keys.d/data.key
Accept=no
SocketMode=0600
```

Ship a tmpfiles.d entry creating `/run/cryptsetup-keys.d` (mode 0700) regardless
of whether socket units already create `ListenStream=` parent directories. It
costs one line and removes a question we would otherwise have to keep answering
across systemd versions.
```

Ship a tmpfiles.d entry creating `/run/cryptsetup-keys.d` (mode 0700) regardless
of whether socket units already create `ListenStream=` parent directories. It
costs one line and removes a question we would otherwise have to keep answering
across systemd versions.

### 3.2 Connection handling

```
on connection(listen_fd, conn_fd):
    volume  = basename(getsockname(listen_fd)) minus ".key"
    peer    = getpeername(conn_fd)           # abstract, leading NUL
    phase   = infix of peer between the random prefix and the volume

    if phase != "/cryptsetup/":
        close(conn_fd)                       # zero bytes: decline, fall through
        return

    # plain phase implies TPM2 already failed for this volume
    pass = cache.get() or ask_passphrase(volume)   # own retry loop on typos
    if not validate(volume, pass): ...
    cache.put(pass)

    maybe_reenroll(volume, pass)             # synchronous, see 4

    write_all(conn_fd, pass)                 # verbatim, no newline
    close(conn_fd)
```

Passphrase acquisition delegates to the same primitives systemd-cryptsetup uses
(`get_password()`, `cryptsetup.c:911`) so the UX and the kernel keyring
behaviour are identical: `id = "cryptsetup:<cescaped device>"`,
`keyring = "cryptsetup"`, `credential = "cryptsetup.passphrase"`,
`icon = "drive-harddisk"`, and the default flags
`ASK_PASSWORD_ACCEPT_CACHED | ASK_PASSWORD_PUSH_CACHE` (`cryptsetup.c:91`).
Accepting the cache means a passphrase already typed for a *non-managed* volume
is picked up without a second prompt; pushing to the cache means the converse
also holds.

## 4. Re-enrollment

Synchronous, before the passphrase is returned. The user is already stopped at a
console prompt, so the added latency is not on an otherwise-unattended path, and
synchronous ordering avoids any risk of the initrd tearing down mid-enrollment.

### 4.1 Preflight

Refuse to touch the LUKS header unless all of these hold. Each one is a case
where re-enrolling is useless or destructive:

| check | why |
|-------|-----|
| a TPM2 device is present and responsive | no TPM means fallback is expected, not a drift; wiping the token would be pure loss |
| the TPM is not in dictionary-attack lockout | sealing would succeed but unsealing keeps failing, so we would churn the header every boot |
| the volume already carries a systemd-tpm2 token, or `enrollIfAbsent` is set | distinguishes "drifted" from "never enrolled" |
| the current PCR values differ from the enrolled policy | if they match, the fallback had some other cause and re-enrolling fixes nothing |

The last check also prevents the pathological loop where enrollment succeeds but
unlock keeps failing for an unrelated reason.

Lockout detection reads `TPM_PT_LOCKOUT_COUNTER` via `TPM2_GetCapability`. This
is not a case we aim to handle gracefully -- a TPM in lockout means the machine
has a bigger problem than a stale PCR binding. The check exists only to stop us
rewriting the LUKS header on every boot of a machine in that state. Log and
decline; do not attempt recovery.

### 4.2 Enrollment

```
systemd-cryptenroll \
    --unlock-key-file=/proc/self/fd/<memfd> \
    --wipe-slot=tpm2 \
    --tpm2-device=<device> \
    --tpm2-pcrs=<spec> \
    <backing device>
```

The passphrase goes in via a memfd rather than argv or `$PASSWORD`. (Note that
`$PASSWORD` does work -- `src/cryptenroll/cryptenroll-password.c:30` -- but it
is undocumented in the man page and leaves the secret readable in `/proc` for
the lifetime of the process.)

Combining `--wipe-slot=tpm2` with enrollment in one invocation is the documented
update idiom, and systemd-cryptenroll(1) states that wiping happens **after**
enrollment with the newly added slot always excluded. This gives the safety
property we want: an interrupted run leaves either the old slot, the new slot, or
both -- never zero. The passphrase slot is untouched in every case.

Open: whether `--unlock-key-file=` strips a trailing newline. We write the exact
bytes ask-password handed us, which should have none, so this may never bite.
But the asymmetry between terminal input (newline-stripped) and key-file input
(verbatim) is a classic source of "correct passphrase rejected" bugs, so it is
worth a deliberate five-minute experiment early in implementation rather than a
confusing failure later.

### 4.3 Verification

After enrollment, test-unseal against the new policy before returning. If the
new slot does not actually unlock, log loudly -- the old slot is already gone at
that point, but the passphrase still works, so the volume is recoverable.

### 4.4 Cost

The passphrase is run through the LUKS2 KDF twice: once by systemd-cryptenroll
to unlock for enrollment, once by systemd-cryptsetup to activate. With argon2id
at typical settings that is a few seconds and up to a gigabyte of memory *twice*
inside the initrd. Acceptable for an interactive fallback path, but worth
measuring, and worth documenting for anyone running an initrd with a tight memory
budget.

## 5. Multiple volumes and shared passphrases

The original framing of this project assumed the daemon would see a passphrase
once and then have to speculatively re-bind every other volume that might share
it, because systemd's kernel-keyring cache would suppress the later prompts.
That is not what happens on the discovery path, and the difference is worth
stating precisely.

`discover_key()` runs at the top of **every** iteration of the unlock loop
(`cryptsetup.c:2735`), gated only on `try_discover_key` -- which is initialized
to `!key_file` and cleared only after a failed attach that actually used it. The
keyring cache is consulted solely inside `get_password()`, which sits behind

    if (token_type < 0 && !key_file && !key_data && !passwords)   /* cryptsetup.c:2742 */

and is therefore reachable only once discovery has already produced nothing.
**Discovery preempts the cache, not the other way around.** For a managed volume
we are always asked first, regardless of what is sitting in the keyring.

So no speculation is needed. Every managed volume opens its own connection pair
to us -- one in the TPM2 phase, one in the plain phase -- and we make the
re-enrollment decision per volume, at the moment that volume is actually being
unlocked. We answer the second and subsequent volumes from our in-process cache,
so the user is still prompted once. A volume whose TPM2 unlock *succeeded* never
reaches the plain phase and is correctly left alone, without us having to
recognize that fact.

Connection count per managed volume: one in the success case (the TPM2-phase
decline), two in the fallback case.

We still interoperate with the keyring in both directions, for the benefit of
*unmanaged* volumes in the same boot: the daemon accepts cached entries, so a
prompt from an unmanaged volume satisfies us without re-prompting, and pushes
its own, so an unmanaged volume unlocked later picks ours up.

## 6. Security model

Automatic re-enrollment silently blesses whatever boot chain is currently
running. Normally an unexpected passphrase prompt *is* the evil-maid signal;
this tool removes it. The counterargument is real but partial: an attacker who
knows the passphrase already has the data. What is genuinely lost is the
*detection* property for an attacker who has tampered with the boot chain and is
waiting for the legitimate user to type the passphrase into it.

Therefore: **consent is mandatory, with no opt-out.** After validating the
passphrase, and before touching the header, the daemon prompts:

    Boot measurements for <volume> have changed since TPM2 enrollment.
    Re-enroll TPM2 against the current state? [y/N]

Consent is requested after validation so a typo never produces a consent prompt.
Declining returns the passphrase and leaves the header alone -- the boot
proceeds normally, the volume simply stays in passphrase-only mode.

### 6.1 Why there is no auto-consent toggle

An earlier draft had an `autoConsent` option for unattended machines. It is
deliberately excluded, because there is no way to implement it that is not
itself tamperable.

A consent flag has to live somewhere the daemon reads at unlock time, which
means inside the initrd -- part of the very boot chain whose integrity is in
question. An attacker positioned to change the measured boot state is, in the
general case, positioned to flip the flag along with it. Auto-consent would then
convert the tool from "repair a broken binding with a human in the loop" into
"silently re-bind to whatever the attacker installed", which is precisely the
attack the PCR binding exists to make visible.

A human at the console answering a prompt is the one signal here that a modified
boot chain cannot forge. Making it optional would make it worthless, so it is
not optional.

The accepted cost: **fully unattended machines cannot use this tool.** That is a
known limitation, not an oversight. A headless server that reboots into a
changed PCR state falls back to a passphrase prompt and stays there until
someone attends to it -- exactly as it would without this tool installed. Those
deployments want signed PCR policies or pcrlock instead (6.2).

Every re-enrollment logs the old and new PCR values so the event is auditable
after the fact.

### 6.2 Relationship to upstream approaches

systemd offers two mechanisms that attack PCR brittleness at the root, and this
tool is an alternative to them, not a replacement:

- **Signed PCR policies** (`systemd-cryptenroll --tpm2-public-key=`): bind to a
  signature over PCR 11 rather than to literal values, so a vendor-signed kernel
  update does not invalidate the policy. The right answer for UKI-based systems,
  and the right answer for unattended ones, but it requires a signing key and a
  build pipeline that produces signatures.
- **systemd-pcrlock**: precomputes an allowlist of expected PCR 0-7 values across
  firmware and boot-loader variation. Powerful, and considerably more machinery.

`tpm2-autoenroll` is the pragmatic third option: accept that the policy will
break, and make repairing it a single keypress instead of a documentation
lookup. It composes with literal-PCR enrollments, which is what most hand-rolled
setups actually use. It is explicitly a tool for attended machines.

## 7. NixOS module

Flake input exposing `nixosModules.default`. Volumes are listed explicitly.

The daemon is **stage-agnostic** (section 9.1), so the module is not namespaced
under `boot.initrd`. It emits the same units into the initrd or the real root
depending on where each volume is actually unlocked.

```nix
services.tpm2-autoenroll = {
  enable = true;

  # Global defaults, overridable per volume.
  tpm2Device = "auto";
  tpm2Pcrs   = [ 7 ];
  wipeSlot   = "tpm2";
  enrollIfAbsent = false;     # only repair drifted bindings, do not create new ones

  volumes.root = {
    device   = "/dev/disk/by-uuid/....";   # backing device
    stage    = "initrd";                   # default
    tpm2Pcrs = [ 7 11 ];
  };

  volumes.backup = {
    device = "/dev/disk/by-uuid/....";
    stage  = "system";                     # unlocked from the booted system
  };
};
```

The attribute name is the *volume* (mapper) name. It must match the crypttab
entry, because that name is what appears in both the socket path and the
bindname.

The module:

- writes the `.socket` unit with one `ListenStream=` per volume in that stage,
  plus the `.service` unit for the daemon, into `boot.initrd.systemd.units`
  and/or `systemd.units` as appropriate
- writes a tmpfiles.d entry for `/run/cryptsetup-keys.d` (3.1)
- writes a daemon config file (JSON) enumerating volumes and their parameters
- adds the daemon, `systemd-cryptenroll`, and the tpm2 libraries to
  `boot.initrd.systemd.storePaths` when any volume is in the initrd stage

Assertions:

- `boot.initrd.systemd.enable` must be true when any volume uses the initrd
  stage; this design depends on systemd in the initrd
- TPM2 support must be enabled in the initrd, so `/dev/tpmrm0` exists by the
  time cryptsetup runs
- each initrd-stage `volumes.<name>` must have a corresponding
  `boot.initrd.luks.devices.<name>`
- that device must **not** set `keyFile`, since a configured key file suppresses
  the discovery path this design relies on (2.2). This assertion is the one most
  likely to save a user from a silently non-functional setup.

## 8. Test harness

NixOS VM tests with `virtualisation.tpm.enable = true` (swtpm). Two tiers.

### Tier 1: state machine, fast and deterministic

Enroll against **PCR 16**, the debug PCR, which is resettable from userspace and
reads as zero after every reboot. Enroll it at runtime with a nonzero value, and
the next boot necessarily mismatches. This exercises the full state machine --
fallback detection, prompt, consent, enroll, verify, silent unlock -- without
involving the boot loader at all.

1. Boot 1: enroll TPM2 against PCR 16 after extending it. Reboot.
2. Boot 2: PCR 16 is zero, policy mismatches. Assert the passphrase prompt
   appears, answer it, assert the consent prompt appears, accept, assert
   `systemd-cryptenroll` ran and the token changed. Reboot.
3. Boot 3: assert the volume unlocks with **no** prompt.

Negative cases to assert alongside:

- declining consent leaves the header unchanged and still boots
- with the daemon enabled and PCRs matching, boot 1 shows no prompt and no
  header write. This proves the attempt-0 empty reply does not break ordinary
  TPM2 unlock, and it is the single most important regression test in the suite
  -- treat it as the canary for systemd upgrades (section 10), not merely as a
  unit test
- a wrong passphrase at the prompt does not produce a consent prompt and does
  not touch the header

### Tier 2: real boot-chain PCR change

`virtualisation.useBootLoader = true` with UEFI/OVMF and a persistent disk across
`machine.shutdown()` / `machine.start()`. Enroll against PCR 12 (kernel command
line, as measured by systemd-stub), then rebuild with a changed
`boot.kernelParams` and boot into the new generation. This is the realistic
version of the scenario the tool exists for.

Budget time for this one. swtpm plus OVMF plus `useBootLoader` plus a persistent
disk is a finicky combination in the NixOS test framework, and failures there
tend to be infrastructure failures rather than product failures. Tier 1 is what
should gate CI; tier 2 is what proves the premise.

### Out of selected scope

A multi-volume test -- two LUKS volumes sharing a passphrase, asserting the
second is answered from cache without a second prompt and re-enrolled
independently -- is not in the chosen test scope, but the behaviour is in scope
for the implementation (section 5) and the test is cheap to add on top of tier 1.
Recommended.

## 9. Implementation notes

Rust. The daemon needs `getpeername`/`getsockname` on AF_UNIX with abstract
names, `sd_listen_fds`-style fd pickup, subprocess control for
`systemd-cryptenroll` and `systemd-ask-password`, a TSS binding for the lockout
counter, and reliable erasure of key material. Static musl build to keep the
initrd closure small.

Secret hygiene: `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)` at startup
(systemd-cryptsetup does exactly this at `cryptsetup.c:2625`, self-deprecatingly
labelled "a delicious drop of snake oil"), zeroize on drop for every buffer
holding a passphrase, and never place a passphrase in argv or the environment.

### 9.1 Stage agnosticism

The daemon must not know or care whether it is running in the initrd or in the
real root. It takes its volume list from its config file and its sockets from
`LISTEN_FDS`, and everything else follows from systemd's calling semantics,
which are identical in both stages.

This falls out correctly rather than by special-casing. The invariant that makes
the whole design sound is **enroll at the point of unlock**: the PCR values read
when we are consulted are, by construction, the values that will be present the
next time that same volume is unlocked at that same point in boot. That holds
for a root volume unlocked in the initrd and equally for a data volume unlocked
from the booted system -- each captures its own stage's PCR state, which is the
correct state for it.

The one thing worth warning about in the module: a **system**-stage volume bound
to PCR 11 or above is binding to values that userspace continues to extend after
the point of measurement. That is a footgun inherent to the PCR choice, not to
this tool, but the module should warn on it because this tool makes such a
configuration easy to create by accident.

## 10. Known risk: an undocumented behaviour is load-bearing

The decline-by-zero-bytes step in 2.3 is **not documented** in crypttab(5). The
man page documents the socket protocol and the per-token-type bindname infixes,
but says nothing about what an empty reply means. The behaviour we rely on falls
out of `iovec_is_set()` requiring `iov_len > 0`
(`src/fundamental/iovec-util-fundamental.h:43`) combined with the dispatch test
at `cryptsetup.c:2044`. It is an implementation detail, not a contract.

If a future systemd treated an empty reply as an error rather than as absent key
data, attempt 0 would fail before reaching the header token, and every managed
volume would fall back to a passphrase prompt on every boot -- degraded, not
unsafe, but a total loss of the feature.

Mitigations, in order of preference:

- The tier 1 regression test above catches this on the first CI run against a
  new systemd. Treat it as a canary for systemd upgrades.
- Consider raising this upstream. A one-line clarification in crypttab(5) --
  that an empty reply means "no key available, continue to the next source" --
  would turn the load-bearing detail into a contract. Worth doing regardless of
  the outcome, since the discussion would surface whether upstream considers
  this an abuse of the interface.
- If upstream rejects the semantics, the fallback design is to replace the
  console password agent (`systemd-ask-password-console.service`) with our own,
  which observes nothing but *owns* the prompt and therefore sees the
  passphrase. That works without any crypttab or keys.d involvement, but means
  competing with plymouth for the tty and reimplementing agent behaviour. It is
  the backup, not the plan.

## 11. Open questions

- Does `systemd-cryptenroll --unlock-key-file=` strip a trailing newline? To be
  settled empirically during implementation (4.2).
- Where exactly should the consent prompt render when plymouth owns the console?
  `systemd-ask-password` handles agent dispatch for us, but a yes/no prompt with
  echo has different UX properties than a passphrase prompt, and plymouth's
  handling of it needs checking.
- Should a declined consent be remembered for the remainder of the boot, so a
  user with five volumes sharing a passphrase is not asked five times? Leaning
  yes, scoped to the daemon's lifetime and keyed by PCR state.
