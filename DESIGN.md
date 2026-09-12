# tpm2-autoenroll design

Status: sections 2-7 implemented and verified; section 8 tier 1 covers both the
daemon and the module, tier 2 not yet built
Target: systemd 260 (verified against 260.2 source, and against a running 260.2)

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

### 2.4 The libcryptsetup token plugin pre-empts all of this on success

Established empirically during implementation, against systemd 260.2. An earlier
draft of 2.3 was incomplete here.

Section 2.2 notes in passing that `cryptsetup.c:2691` gates the libcryptsetup
token-plugin path on `if (!key_file && use_token_plugins())`, and treats that as
one more door closed by configuring field 3. But look at the gate from the other
side. Our configuration is *precisely* `key_file == NULL`, so with the plugin
present the condition is **true**, and this block sits **before** the retry loop:

    if (!key_file && use_token_plugins()) {
            r = crypt_activate_by_token_pin_ask_password(...);
            if (r >= 0) {
                    log_debug("Volume %s activated with a LUKS token.", volume);
                    return 0;              /* cryptsetup.c:2701 */
            }
            log_debug_errno(r, "Token activation unsuccessful ...");
    }

`use_token_plugins()` (`cryptsetup.c:1484`) returns true whenever systemd was
built with `HAVE_LIBCRYPTSETUP_PLUGINS` and `crypt_token_external_path()` finds
the plugin directory. On any distribution shipping
`libcryptsetup-token-systemd-tpm2.so` -- nixpkgs does -- that is the normal case.

So on a healthy volume the plugin unseals the token and returns at 2701. The
retry loop never runs, `discover_key()` is never called, and **the daemon is not
contacted at all.** Not contacted and declining; simply absent from the path.

This does not break the design, and on reflection it is a small gift:

- **The fallback path is unaffected**, which is the only path that matters.
  When unsealing fails, `crypt_activate_by_token_pin_ask_password()` returns
  negative, control falls through to the retry loop, and 2.3 plays out exactly
  as written: attempt 0 reaches us as `/cryptsetup-tpm2/`, attempt 1 as
  `/cryptsetup/`. Verified.
- **On the success path we cost nothing at all** rather than costing one
  connection.

What it changes is the *scope* of the section 10 risk. The zero-byte decline is
load-bearing only on the discovery route, and the discovery route is taken only
when the token plugin is unavailable or fails. That is not a corner case: an
initrd assembled without `libcryptsetup-token-systemd-tpm2.so` in its closure
takes the discovery route on every boot, and the initrd is this tool's primary
stage. Both routes therefore have to work, and both are tested (section 8).

Note for the NixOS module: it must **not** attempt to suppress the plugin to
force the discovery route. Both routes are correct, and the one that skips us
entirely is the cheaper one.

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
The `initrd-switch-root.target` lines below apply only to the initrd copy of the
unit and are omitted from the system-stage copy.

```
[Unit]
DefaultDependencies=no
Before=cryptsetup-pre.target
Before=systemd-cryptsetup@root.service    # one per volume in this stage
Wants=... (via [Install] WantedBy=)       # the same units
Conflicts=initrd-switch-root.target       # initrd stage only
Before=initrd-switch-root.target          # initrd stage only

[Socket]
ListenStream=/run/cryptsetup-keys.d/root.key
ListenStream=/run/cryptsetup-keys.d/data.key
Accept=no
SocketMode=0600
DirectoryMode=0700
```

Two corrections to an earlier draft, both found while building section 7.

**`cryptsetup-pre.target` is not sufficient on its own.** It looked like the
natural anchor because it is the target `systemd-cryptsetup@.service` is ordered
after in both stages. But it carries `RefuseManualStart=yes` and is pulled in
only by the cryptsetup generator, so on a machine where it never starts,
ordering before it constrains nothing. What actually guarantees we are listening
is naming the instances: one `Before=` and one `WantedBy=` per
`systemd-cryptsetup@<volume>.service` in that stage. The `Wants` is what starts
the socket at all -- it is deliberately not wanted by `sockets.target`, which in
the initrd sits behind `basic.target` and is far too late -- and the `Before` is
what makes it start first. nixpkgs' own clevis unit is wired the same way. The
`Before=cryptsetup-pre.target` line stays as documentation of intent; it is the
per-instance pair that carries the weight.

**The tmpfiles.d entry is unnecessary.** An earlier draft hedged: ship one
"regardless of whether socket units already create `ListenStream=` parent
directories". systemd.socket(5) settles the question -- they are created
automatically, and `DirectoryMode=` is the setting that picks their mode. One
line in `[Socket]` replaces a tmpfiles.d entry whose ordering in the initrd we
would otherwise have had to prove was early enough, which was the real cost the
hedge was trying to avoid paying.

### 3.2 Connection handling

```
on connection(listen_fd, conn_fd):
    volume  = basename(getsockname(listen_fd)) minus ".key"
    peer    = getpeername(conn_fd)           # abstract, leading NUL
    phase   = infix of peer between the random prefix and the volume

    if phase != "/cryptsetup/" or volume not in config:
        close(conn_fd)                       # zero bytes: decline, fall through
        return

    # plain phase implies TPM2 already failed for this volume
    device = config[volume].device
    pass   = None

    for candidate in cache:                  # section 5: ask the user once
        if validate(device, candidate):
            pass = candidate
            break

    for attempt in 0..TRIES:                 # our own retry loop, see 2.3
        if pass: break
        for candidate in ask_passphrase(device, accept_cached = attempt == 0):
            if validate(device, candidate):
                pass = candidate
                cache.put(pass)
                break

    if not pass:
        close(conn_fd)                       # decline; stock behaviour resumes
        return

    maybe_reenroll(volume, pass)             # synchronous, see 4

    write_all(conn_fd, pass)                 # verbatim, no newline
    close(conn_fd)
```

`validate()` failing is not an error condition: it is the ordinary outcome of a
typo, or of a cached passphrase that belongs to a different volume. An error
condition -- a device that cannot be read at all -- is distinguished from it and
declines rather than re-asking, since no amount of retyping will conjure the
device (cryptsetup(8) return code 2 means "bad passphrase" specifically).

Passphrase acquisition delegates to the same primitives systemd-cryptsetup uses
(`get_password()`, `cryptsetup.c:911`) so the UX and the kernel keyring
behaviour are identical: `id = "cryptsetup:<cescaped device>"`,
`keyring = "cryptsetup"`, `credential = "cryptsetup.passphrase"`,
`icon = "drive-harddisk"`, and the default flags
`ASK_PASSWORD_ACCEPT_CACHED | ASK_PASSWORD_PUSH_CACHE` (`cryptsetup.c:91`).
Accepting the cache means a passphrase already typed for a *non-managed* volume
is picked up without a second prompt; pushing to the cache means the converse
also holds.

### 3.3 Validation is what makes the rest of it safe

`validate()` above is not a detail. Three separate things depend on it:

- **Accepting a cached passphrase.** A secret from the kernel keyring was typed
  for *some* volume, not necessarily this one. Returning it unchecked spends the
  single attempt of 2.3 on a guess.
- **Retrying a typo.** Same argument, and it is the more common case.
- **The consent prompt (6).** Consent is asked only after validation, so a typo
  never produces one.

It is implemented as `cryptsetup open --test-passphrase` with the candidate in a
memfd, plus `--disable-external-tokens --disable-keyring` so that the answer is a
statement about the *passphrase* rather than about some other unlock path. On
this code path the TPM2 token has just failed, so a token succeeding here would
be precisely the wrong thing to believe.

`systemd-ask-password` is asked with `--multiple`, because with
`--accept-cached` and several volumes unlocked earlier in the boot the keyring
may hold more than one candidate, and taking only the first would let a
passphrase belonging to another volume mask the one that works. Each candidate
is validated in turn, capped at four per prompt so a long keyring cannot cost an
unbounded number of KDF passes. A retry never passes `--accept-cached`: the
cached entry is what was just rejected, and asking for it again would spin the
loop without the user being given a chance to type.

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
| exactly one such token | `--wipe-slot=tpm2` removes every one of them, so with two we would destroy a binding that is not ours |
| it is a plain PCR policy, not a signed or pcrlock one | those are policies we cannot recreate, so replacing one is a downgrade (6.2) |
| the current PCR values differ from the enrolled policy | if they match, the fallback had some other cause and re-enrolling fixes nothing |

The last check also prevents the pathological loop where enrollment succeeds but
unlock keeps failing for an unrelated reason.

Lockout detection reads `TPM_PT_PERMANENT` via `TPM2_GetCapability` and tests
`inLockout`, alongside `TPM_PT_LOCKOUT_COUNTER` and `TPM_PT_MAX_AUTH_FAIL` for
the log line. An earlier draft named only the counter, which is the wrong
question: a nonzero counter is ordinary, and what matters is whether the TPM is
presently refusing authorizations. This is not a case we aim to handle
gracefully -- a TPM in lockout means the machine has a bigger problem than a
stale PCR binding. The check exists only to stop us rewriting the LUKS header on
every boot of a machine in that state. Log and decline; do not attempt recovery.

Reading the properties doubles as the "is a TPM present and responsive" check:
a TPM that answers this answers anything else we need.

#### How the drift check is actually done

The enrolled side is read from the LUKS2 header: the `systemd-tpm2` token
records the PCR selection, the bank, and `tpm2-policy-hash`, the digest the
volume was sealed against.

The current side is computed **by the TPM**, in a trial session: `PolicyPCR`
over the registers as they stand right now, then `PolicyAuthValue` if the token
carries a PIN, which is the sequence `tpm2_calculate_sealing_policy()` builds.
A trial session authorizes nothing; computing this digest is what it is for.
Passing an empty `pcrDigest` to `TPM2_PolicyPCR` is what makes it a question
about the machine's present state rather than a check against a value we supply.

The alternative was to reimplement systemd's policy construction in software,
which means owning a copy of its hashing and keeping that correct across systemd
releases. Asking the hardware that will later be asked to unseal is less code
and a better authority. The test that matters is in section 8: a volume whose
PCRs have not moved must come out as *matching*, and it only does if the digest
computed here equals the one `systemd-cryptenroll` sealed with.

This check is deliberately conservative. A token whose blob has been corrupted,
or whose SRK no longer exists, would in fact be repaired by re-enrolling -- but
it presents identically to one where re-sealing would change nothing, so we
decline both. Declining costs a manual repair; guessing costs a header rewrite
on every boot, forever.

Talking to `/dev/tpmrm0` directly, rather than through a TSS binding or
tpm2-tools, keeps the static musl build of section 9 and puts neither in the
initrd. The price is marshalling four commands by hand, which is affordable
because none of them takes a session or an authorization.

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

The `<spec>` keeps the bank the old token named, as `PCR:BANK` pairs -- `16:sha256`
rather than bare `16`. A repair should reproduce the enrollment it replaces, not
quietly move it to whichever bank systemd would pick by default today.

The selection likewise comes from the token being repaired rather than from
`tpm2Pcrs` in the config. The config describes what a *fresh* enrollment would
bind to; narrowing or widening an existing binding is a policy change, and not
one to make silently on a fallback path. `tpm2Pcrs` is consulted only when there
is no token to copy, i.e. under `enrollIfAbsent`.

Open: whether `--unlock-key-file=` strips a trailing newline. We write the exact
bytes ask-password handed us, which should have none, so this may never bite.
But the asymmetry between terminal input (newline-stripped) and key-file input
(verbatim) is a classic source of "correct passphrase rejected" bugs. The tier 1
test exercises the real path end to end with a passphrase that has no newline,
so the question is now narrower than it was: what remains untested is a
passphrase that *does* carry one, which our own prompt should never produce.

### 4.3 Verification

After enrollment, test-unseal against the new policy before returning. If the
new slot does not actually unlock, log loudly -- the old slot is already gone at
that point, but the passphrase still works, so the volume is recoverable.

There are two ways to do this, and which one is available depends on the same
thing section 2.4 turns on:

- **`cryptsetup open --test-passphrase --token-only --token-id=N`.** With
  `--token-only` there is no passphrase fallback, so success is a real TPM2
  unseal and nothing else. This is the strong form, and it needs
  `libcryptsetup-token-systemd-tpm2.so`.
- **Comparing the new token's policy against the current PCRs**, using the same
  trial session as the drift check (4.1). Available always, and it covers the
  failure this tool can actually cause -- sealing against the wrong state. It
  would not notice an unusable SRK.

Try the first, fall back to the second, and say in the log which one was used.
An initrd trimmed of the token plugin gets the weaker check, which is the right
trade: refusing to verify at all would mean either skipping verification or
refusing to repair on exactly the systems that need repairing most.

On **nixpkgs the strong form is never available**, established while building
this: systemd installs the plugin into its own output, and `pkgs.cryptsetup`'s
plugin directory is empty, so the standalone CLI cannot load it even on a full
system. Most distributions install both into `${libdir}/cryptsetup/` and do get
the strong check. A `--external-tokens-path=` pointing at systemd's directory
would recover it, but that is a path only the NixOS module could know, and the
policy comparison already covers the failure mode this tool can cause. Noted
rather than fixed.

Note that `cryptsetup open --token-only` reports "no token could unlock this"
as exit status 1 with **nothing on stderr**, which reads like an argument error
and is not what the man page's return-code table would suggest. Verified
directly against 2.8.6.

### 4.4 Cost

The passphrase is run through the LUKS2 KDF three times on the re-enrollment
path: once by us to validate it (3.3), once by systemd-cryptenroll to unlock for
enrollment, once by systemd-cryptsetup to activate. With argon2id at typical
settings that is a few seconds and up to a gigabyte of memory *each time* inside
the initrd. Acceptable for an interactive fallback path, but worth measuring, and
worth documenting for anyone running an initrd with a tight memory budget.

Every rejected candidate adds a further pass: a typo costs one, and so does each
cached passphrase that turns out to belong to a different volume. That is the
price of never spending our single attempt on an unchecked secret, and it is
bounded -- three prompts, four candidates each.

The validation pass is paid on every fallback unlock, including the ones that do
not re-enroll (consent declined, preflight refused). The other two are paid only
when enrollment actually happens.

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

Every re-enrollment logs the old and new policy digests and the current PCR
values, so the event is auditable after the fact.

Two implementation details follow from consent being a prompt rather than a
setting. It goes out through `systemd-ask-password` like the passphrase does, so
whichever agent owns the console renders it -- but with `--echo=yes`, since the
answer is not a secret, and with **no** `--keyname=`, because pushing "y" into
the `cryptsetup` keyring would leave it sitting there as a candidate passphrase
for the next volume. And anything that is not an explicit `y`/`yes` is a
refusal, including a timeout, a closed prompt, or an agent that failed outright:
refusing costs a manual repair, while assuming consent re-binds the volume to
whatever boot chain is running.

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

An earlier draft had a `wipeSlot` global here. It is dropped: `enroll.rs` passes
`--wipe-slot=tpm2` unconditionally and 7.1 has no field to carry anything else,
so the option would have been a knob that did nothing.

The module:

- writes the `.socket` unit with one `ListenStream=` per volume in that stage,
  plus the `.service` unit for the daemon, into `boot.initrd.systemd.units`
  and/or `systemd.units` as appropriate
- writes a daemon config file (JSON) enumerating volumes and their parameters
- adds the daemon and the three binaries it shells out to
  (`systemd-ask-password`, `systemd-cryptenroll`, `cryptsetup`) to
  `boot.initrd.systemd.storePaths` when any volume is in the initrd stage, and
  names the same packages in the service's `path` so the initrd's systemd is the
  one that gets used

The last point is why the package ships **unwrapped**. A `wrapProgram --prefix
PATH` would be the obvious way to make the daemon self-contained, but it puts
both `systemd` and `cryptsetup` in the package's own closure, and the initrd
then copies a second full systemd no matter how carefully the storePaths list
names individual binaries. PATH belongs to whoever knows the stage, which is the
module.

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

### 7.1 Config file schema

The contract between the module and the daemon. Default path
`/etc/tpm2-autoenroll/config.json`, overridable with `--config=`.

```json
{
  "volumes": {
    "root": {
      "device": "/dev/disk/by-uuid/....",
      "tpm2Device": "auto",
      "tpm2Pcrs": [7, 11],
      "enrollIfAbsent": false
    }
  }
}
```

The key is the volume (mapper) name, matching both the socket path and the
bindname. `device` is the backing device -- what holds the LUKS2 header -- and is
the one field with no default: without it the daemon cannot validate a
passphrase, so a volume that lacks it is not managed.

Values arrive **already resolved**. The module merges its global defaults before
writing the file, so exactly one component knows what a default is, and the
daemon's copy of the schema stays a flat read.

Three rules about failure, all chosen so a bad config degrades rather than
breaks a boot:

- A **missing or unparseable file** is logged and treated as "manage nothing".
  The daemon still serves its sockets and declines every connection, which is
  the same outcome as not being installed. Exiting instead would leave
  systemd-cryptsetup waiting on a connection sitting in a backlog nobody
  accepts from.
- A **malformed volume entry** is dropped with a warning; its neighbours are
  unaffected, the same way one malformed `ListenStream=` does not cost the other
  volumes their sockets.
- An **unrecognised key** is warned about, not rejected, so a config written by a
  newer module still configures the fields an older daemon understands.

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
  unit test.

  Because of 2.4 this has to be asserted **twice**, once per route. With the
  libcryptsetup token plugin available the daemon is never contacted, so the
  only thing to assert is the user-visible property: the volume unlocks and
  nothing prompts. Setting `SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0` on the
  `systemd-cryptsetup@` unit (systemd's own debug switch, `cryptsetup.c:1506`)
  forces the discovery route, and it is that case which asserts the zero-byte
  decline specifically. Asserting only the default route would leave the
  load-bearing behaviour untested
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

### Multi-volume and retry cases

Added to tier 1 alongside the canary, since both are cheap once two volumes
exist:

- two LUKS volumes sharing a passphrase, asserting the second is answered from
  the daemon's cache with no second prompt (section 5), and that the refusal
  given for the first covers the second as well (section 11).
- a wrong passphrase at the prompt, asserting the daemon asks again rather than
  returning it, that exactly one passphrase reaches systemd-cryptsetup, and that
  the header is untouched. This is the observable form of 2.3's "we get one
  shot": if validation regressed, systemd-cryptsetup would burn an attempt on
  the typo and the assertion on the retry line would fail.

### The preflight cases

Three volumes are enough to reach all of them, and the PCR 16 trick means each
is a `systemctl start` rather than a reboot:

- **drifted, consent refused** -- the header digest must be byte-identical
  afterwards. This is the section 6 guarantee, and the cheapest thing to get
  subtly wrong.
- **drifted, consent given** -- the header digest must change, the token must
  move to a different index (`--wipe-slot=tpm2` removes the old, enrollment adds
  the new), and the daemon must report verifying the result. Then, with the PCRs
  still where they were, restarting the volume must unlock it with **no prompt
  at all**. That last step is section 8's "boot 3" without a reboot, and it is
  what distinguishes a real repair from a plausible-looking header write.
- **not drifted** -- a volume that reaches the plain phase while its policy still
  matches the PCRs must be declined, and must never reach the consent prompt.
  Manufactured by re-sealing against the live PCR value and then mangling the
  token's blob, which breaks unsealing while leaving `tpm2-policy-hash` alone.

  This case carries more weight than its size suggests: it passes only if the
  digest the daemon computes in a TPM trial session equals the one
  `systemd-cryptenroll` sealed with. Two independent computations, from opposite
  directions, asserted equal. If the trial-session approach of 4.1 is ever wrong,
  this is the test that says so.
- **never enrolled** -- a volume with no systemd-tpm2 token and `enrollIfAbsent`
  unset must be left exactly as it is.

### The module cases

The cases above all run against hand-written units and a hand-written config
file, which means they say nothing about whether section 7 produces working
ones. A second tier 1 machine is configured **only** through
`services.tpm2-autoenroll` -- the sole thing written by hand is `/etc/crypttab`,
because NixOS has no stage-2 equivalent of `boot.initrd.luks.devices`.

- the socket is listening **before** the volume it serves, with nothing in the
  test arranging that. This is the assertion that would have caught the
  `cryptsetup-pre.target` mistake in 3.1: the socket is started by its
  `WantedBy=` on `systemd-cryptsetup@<volume>.service` and ordered by the
  matching `Before=`, and if either were missing the volume would still unlock
  -- silently losing the feature rather than failing.
- `/run/cryptsetup-keys.d` comes out `0700` with no tmpfiles.d entry anywhere in
  the configuration, which is the other half of the same correction.
- the config file's contents equal the module's globals merged with each
  volume's overrides. One volume takes every default and one overrides every
  field, so 7.1's "values arrive already resolved" is visible in the file rather
  than merely asserted.
- neither unit is running before a volume needs one, and on a healthy unlock the
  *service* is never started at all -- 2.4's "we cost nothing" as an observable
  property rather than an argument.
- a drift is repaired end to end over the generated wiring, so a passing module
  test is not just a passing unit-file diff.

These run at `stage = "system"`, where the test can drive the units directly.
The initrd stage differs only in which attribute set the same two units are
written into; that it assembles -- config file, daemon, and the three helper
binaries with their libraries, all present in the cpio -- is checked by building
the initrd, not by booting one. A tier 2 test is what would boot it.

## 9. Implementation notes

Rust. The daemon needs `getpeername`/`getsockname` on AF_UNIX with abstract
names, `sd_listen_fds`-style fd pickup, subprocess control for
`systemd-cryptenroll`, `systemd-ask-password` and `cryptsetup`, a way to ask the
TPM about lockout state and policy digests, and reliable erasure of key
material. Static musl build to keep the initrd closure small.

An earlier draft said "a TSS binding" for the TPM half. That turned out to be
unnecessary: the four commands we need (`GetCapability`, `PCR_Read`,
`StartAuthSession`, `PolicyPCR`/`PolicyAuthValue`/`PolicyGetDigest`,
`FlushContext`) take no sessions and no authorizations, so marshalling them by
hand onto `/dev/tpmrm0` is a few hundred lines and keeps both tpm2-tss and
tpm2-tools out of the initrd -- and keeps the static build possible, which
linking tpm2-tss would not.

The runtime dependencies are therefore three binaries on `PATH`:
`systemd-ask-password`, `systemd-cryptenroll` and `cryptsetup`. The first two
were always expected; `cryptsetup` arrives with passphrase validation (3.3) and
is reused for the strong form of verification (4.3). Supplying them is the
caller's job rather than the package's, for the closure reason in section 7 --
and getting it wrong is quiet rather than loud, since a missing `cryptsetup`
makes every passphrase fail validation and so looks from the outside exactly
like a user who typed it wrong.

Secret hygiene: `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)` at startup
(systemd-cryptsetup does exactly this at `cryptsetup.c:2625`, self-deprecatingly
labelled "a delicious drop of snake oil"), zeroize on drop for every buffer
holding a passphrase, and never place a passphrase in argv or the environment.
Passphrases reach child processes through a memfd named by `/proc/self/fd/N`,
with `FD_CLOEXEC` cleared in the `pre_exec` hook so that exactly one child sees
it and nothing is left readable in the parent's descriptor table afterwards.

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
to a register that userspace continues to extend after the point of measurement
would seal against a state that has already moved on by the next unlock. That is
a footgun inherent to the PCR choice, not to this tool, but the module warns on
it because this tool makes such a configuration easy to create by accident.

An earlier draft said "PCR 11 or above", and the module test caught that being
wrong on its first run: it enrolls against **PCR 16**, the debug PCR, which
nothing extends unless asked to, and the warning fired. The registers systemd's
userspace tooling actually extends are 11 (`systemd-pcrphase`, at `leave-initrd`
and again at sysinit and ready), 12 (kernel command line and credentials), 13
(system extension images) and 15 (machine ID and file system identity). 14 is
the shim MOK list, extended in the boot-loader phase and not after; 16 is the
debug PCR; 17-22 are D-RTM. Warning on those would be a false positive on every
use of the debug PCR, including this tool's own tests -- which is exactly how a
warning gets trained away.

## 10. Known risk: an undocumented behaviour is load-bearing

The decline-by-zero-bytes step in 2.3 is **not documented** in crypttab(5). The
man page documents the socket protocol and the per-token-type bindname infixes,
but says nothing about what an empty reply means. The behaviour we rely on falls
out of `iovec_is_set()` requiring `iov_len > 0`
(`src/fundamental/iovec-util-fundamental.h:43`) combined with the dispatch test
at `cryptsetup.c:2044`. It is an implementation detail, not a contract.

**Status: confirmed to hold on systemd 260.2.** With the token plugin disabled
so that the discovery route is taken, systemd-cryptsetup consults the socket as
`/cryptsetup-tpm2/<volume>`, accepts the zero-byte reply as absent key data, and
proceeds to unlock from the LUKS2 header token:

    tpm2-autoenrolld: volume "autotest": tpm2 phase, declining with zero bytes
    systemd-cryptsetup: Automatically discovered security TPM2 token unlocks volume.

Per 2.4, this route is reached only when the libcryptsetup token plugin is
absent or fails, which narrows the blast radius of a future systemd change but
does not remove it: an initrd without the plugin takes this route on every boot.

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

- Does `systemd-cryptenroll --unlock-key-file=` strip a trailing newline? Still
  to be settled empirically (4.2), though systemd-cryptenroll(1) leans towards
  "no": it says the file "has to only contain the full key". The validation step
  (3.3) narrows the blast radius -- we now know the passphrase is right before
  cryptenroll sees it, so a failure there is unambiguously cryptenroll's
  handling of the bytes rather than a wrong secret.
- Where exactly should the consent prompt render when plymouth owns the console?
  `systemd-ask-password` handles agent dispatch for us, but a yes/no prompt with
  echo has different UX properties than a passphrase prompt, and plymouth's
  handling of it needs checking.
- **Settled: yes.** A declined consent is remembered for the daemon's lifetime,
  keyed by the policy digest the current PCRs produce. Two volumes reach the
  same key only when they are bound to the same registers holding the same
  values, so one refusal answers for all of them and a boot state that differs
  at all is asked about afresh. Implemented and covered by the tier 1 test.
