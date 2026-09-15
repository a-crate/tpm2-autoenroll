# Tier-1 canary test (DESIGN.md section 8).
#
# The claim under test is the one DESIGN.md section 10 flags as load-bearing and
# undocumented: replying to the TPM2-phase connection with zero bytes leaves
# `iovec_is_set(key_data)` false, so the dispatch at cryptsetup.c:2044 falls
# through to the LUKS2 header token and ordinary TPM2 unlocking still works.
#
# Assertions, in order of importance:
#
#   1. With the daemon's socket installed and the PCR policy satisfied, the
#      volume unlocks silently. If this breaks, every managed volume prompts on
#      every boot and the tool is worthless -- so this is the regression test to
#      run first against any new systemd.
#   2. With the policy broken, the daemon is reached in the plain phase and the
#      passphrase it returns activates the volume.
#   3. A wrong passphrase is retried by the daemon rather than handed to
#      systemd-cryptsetup, which would spend the one attempt we get (2.3).
#   4. A second volume sharing the passphrase is answered from the daemon's
#      cache without a second prompt (section 5).
#   5. A header whose PCR selection disagrees with the config is left alone
#      without a consent prompt, since the header is not a source of policy.
#   6. So is a PIN enrollment, which a repair would make TPM-only, and so is
#      any volume on a machine set up for a signed PCR policy.
#   7. Once every configured volume has been served the daemon exits, taking
#      its sockets and its passphrase cache with it, and the next unlock
#      starts it again.
#   8. A root process outside the volume's systemd-cryptsetup@ unit gets
#      nothing, even when it binds the plain-phase name.
#
# PCR 16 is the debug PCR: extendable from userspace, which lets us manufacture
# the policy mismatch in place. No reboot and no boot loader, so the test is
# fast enough to gate CI. The volumes are unlocked from the booted system rather
# than the initrd, which section 9.1 says is the same code path.
{ pkgs, tpm2-autoenrolld }:

let
  passphrase = "correct-horse-battery-staple";
  wrongPassphrase = "not-the-passphrase";

  volumes = {
    autotest = "/dev/vdb";
    autotest2 = "/dev/vdc";
    autotest3 = "/dev/vdd";
    autotest4 = "/dev/vde";
  };

  answerPassphrase = import ./answer-passphrase.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "tpm2-autoenroll-socket-core";

  nodes.machine = { lib, pkgs, ... }: {
    virtualisation.tpm.enable = true;
    virtualisation.emptyDiskImages = [ 512 512 512 512 ];
    virtualisation.memorySize = 2048;

    environment.systemPackages = [
      pkgs.cryptsetup
      pkgs.tpm2-tools
      tpm2-autoenrolld
      answerPassphrase
    ];

    # Field 3 is "-": no key file configured, which is what makes
    # systemd-cryptsetup set try_discover_key and consult our socket
    # (cryptsetup.c:2712). A path here instead would force the key-file branch
    # and the header token would never be read -- DESIGN.md section 2.2.
    #
    # noauto keeps the unlock under the test's control rather than boot ordering.
    environment.etc.crypttab.text =
      lib.concatMapStrings
        (line: line + "\n")
        (lib.mapAttrsToList
          (volume: device: "${volume} ${device} - noauto,tpm2-device=auto")
          volumes);

    # The crypttab drives systemd-cryptsetup; this drives the daemon, which
    # binds one socket per volume itself, including creating
    # /run/cryptsetup-keys.d.
    environment.etc."tpm2-autoenroll/config.json".text = builtins.toJSON {
      volumes = lib.mapAttrs (_: device: {
        inherit device;
        pcrs = [ 16 ];
      }) volumes;
    };


    # The same Wants=/After= drop-in the module installs: the daemon exits once
    # it has served every volume, and this is what brings it back for the next
    # unlock. The test still drives the cryptsetup units by hand.
    systemd.units."systemd-cryptsetup@.service" = {
      overrideStrategy = "asDropin";
      text = ''
        [Unit]
        Wants=tpm2-autoenrolld.service
        After=tpm2-autoenrolld.service
      '';
    };

    systemd.services.tpm2-autoenrolld = {
      description = "TPM2 auto-enrollment key agent";
      before = [ "cryptsetup-pre.target" ];
      unitConfig.DefaultDependencies = "no";
      # The package carries no PATH of its own, so the caller names the three
      # binaries the daemon shells out to -- systemd-ask-password,
      # systemd-cryptenroll and cryptsetup. Leaving cryptsetup off is a quiet
      # failure rather than a loud one: passphrase validation would fail for
      # every candidate and the daemon would decline every volume, which looks
      # from the outside like a wrong passphrase.
      path = [ pkgs.systemd pkgs.cryptsetup ];
      serviceConfig = {
        # Type=notify: the daemon says so once every socket is listening, which
        # is what makes "before cryptsetup" mean anything.
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = lib.getExe tpm2-autoenrolld;
      };
    };
  };


  # Two routes reach a TPM2 unlock, and which one runs depends on whether
  # libcryptsetup's external token plugin is installed:
  #
  #   * cryptsetup.c:2691 gates `crypt_activate_by_token_pin_ask_password()` on
  #     `!key_file && use_token_plugins()`. Our configuration leaves the key
  #     file empty, so with the plugin present this fires *before* the retry
  #     loop and returns 0 -- the daemon is never contacted at all.
  #   * without the plugin (a trimmed initrd, say) that call fails, control
  #     falls into the retry loop, and `discover_key()` consults our socket.
  #     This is where the zero-byte decline is load-bearing.
  #
  # Both are tested. `SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0` is systemd's own
  # documented switch for turning the plugin path off (cryptsetup.c:1506).
  testScript = ''
    import re

    PASSPHRASE = ${builtins.toJSON passphrase}
    WRONG = ${builtins.toJSON wrongPassphrase}
    VOLUME = "autotest"
    DEVICE = "/dev/vdb"
    VOLUME2 = "autotest2"
    VOLUME3 = "autotest3"
    DEVICE2 = "/dev/vdc"
    DEVICE3 = "/dev/vdd"
    UNIT = f"systemd-cryptsetup@{VOLUME}.service"
    UNIT2 = f"systemd-cryptsetup@{VOLUME2}.service"
    UNIT3 = f"systemd-cryptsetup@{VOLUME3}.service"
    VOLUME4 = "autotest4"
    DEVICE4 = "/dev/vde"
    UNIT4 = f"systemd-cryptsetup@{VOLUME4}.service"
    PIN = "1234"
    CRYPTENROLL = "${pkgs.systemd}/bin/systemd-cryptenroll"
    DROPIN_DIR = f"/run/systemd/system/{UNIT}.d"


    def daemon_log_lines():
        out = machine.succeed(
            "journalctl -u tpm2-autoenrolld.service --no-pager -o cat || true"
        )
        return out.splitlines()


    class LogWatch:
        """Only look at daemon output produced after the watch was taken, so an
        earlier subtest's lines cannot satisfy a later subtest's assertion."""

        def __init__(self):
            self.mark = len(daemon_log_lines())

        def new(self):
            return "\n".join(daemon_log_lines()[self.mark:])


    def header_digest(device):
        return machine.succeed(f"cryptsetup luksDump {device} | sha256sum").split()[0]


    def pending_password_requests():
        return machine.succeed(
            "ls /run/systemd/ask-password/ 2>/dev/null | grep '^ask\\.' || true"
        ).strip()


    def format_and_enroll(device):
        # pbkdf2 with few iterations: argon2id would spend seconds and a
        # gigabyte per unlock, and the KDF is not what is under test here.
        # The daemon adds a KDF pass of its own for validation, so this keeps
        # the whole test cheap rather than only the unlock.
        machine.succeed(
            f"echo -n {PASSPHRASE} | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --batch-mode {device} -"
        )
        machine.succeed(
            f"PASSWORD={PASSPHRASE} {CRYPTENROLL} "
            f"--tpm2-device=auto --tpm2-pcrs=16 {device}"
        )
        machine.succeed(f"cryptsetup luksDump {device} | grep -q systemd-tpm2")


    def token_index(device):
        """Which token slot the systemd-tpm2 enrollment occupies, or None."""
        import json

        meta = json.loads(
            machine.succeed(f"cryptsetup luksDump --dump-json-metadata {device}")
        )
        for index, token in meta.get("tokens", {}).items():
            if token.get("type") == "systemd-tpm2":
                return int(index)
        return None


    def rewrite_token(device, edit):
        """Export the systemd-tpm2 token, pass it through edit(), and put it
        back. Needs no key, which is exactly why the header cannot be trusted
        as a source of policy."""
        import json

        # Not necessarily token 0: systemd-cryptenroll adds the new token before
        # wiping the old one, so a re-enrolled volume's token has moved up.
        index = token_index(device)
        assert index is not None, (
            f"token_index({device}) returned None, expected a systemd-tpm2 token "
            "to rewrite"
        )

        token = json.loads(
            machine.succeed(f"cryptsetup token export --token-id {index} {device}")
        )
        edit(token)

        machine.succeed(f"cryptsetup token remove --token-id {index} {device}")
        machine.succeed(
            f"cat > /tmp/token.json <<'EOF'\n{json.dumps(token)}\nEOF"
        )
        machine.succeed(
            f"cryptsetup token import --token-id {index} --json-file /tmp/token.json {device}"
        )


    def mangle_token_blob(device):
        """Break unsealing without touching the policy or the PCRs.

        The sealed blob is what the TPM hands back a key from; replacing it with
        something that is still valid base64 but is not a TPM object makes every
        unseal attempt fail, while tpm2-policy-hash -- the thing the daemon
        compares against -- stays exactly as enrolled."""

        def flatten(value):
            # systemd writes this either as one base64 string or as an array of
            # them (key sharding); both spellings are live.
            core = value.rstrip("=")
            return "A" * len(core) + value[len(core):]

        def edit(token):
            blob = token["tpm2-blob"]
            token["tpm2-blob"] = (
                [flatten(b) for b in blob] if isinstance(blob, list) else flatten(blob)
            )

        rewrite_token(device, edit)


    def set_token_plugin(enabled):
        if enabled:
            machine.succeed(f"rm -rf {DROPIN_DIR}")
        else:
            machine.succeed(f"mkdir -p {DROPIN_DIR}")
            machine.succeed(
                f"printf '[Service]\\nEnvironment=SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0\\n'"
                f" > {DROPIN_DIR}/no-token-plugin.conf"
            )
        machine.succeed("systemctl daemon-reload")


    machine.wait_for_unit("multi-user.target")
    machine.wait_for_file("/dev/tpmrm0")
    # Nothing wants the daemon until a volume is started, so bring it up by
    # hand to look at its sockets.
    machine.succeed("systemctl start tpm2-autoenrolld.service")

    with subtest("the daemon bound a socket for every configured volume"):
        mode = machine.succeed("stat -c %a /run/cryptsetup-keys.d").strip()
        assert mode == "700", (
            f"stat -c %a /run/cryptsetup-keys.d returned {mode!r}, expected "
            "'700': the daemon creates the directory it listens in"
        )
        for volume in (VOLUME, VOLUME2, VOLUME3, VOLUME4):
            machine.succeed(f"test -S /run/cryptsetup-keys.d/{volume}.key")
        mode = machine.succeed(
            f"stat -c %a /run/cryptsetup-keys.d/{VOLUME}.key"
        ).strip()
        assert mode == "600", (
            f"stat -c %a /run/cryptsetup-keys.d/{VOLUME}.key returned {mode!r}, "
            "expected '600': the socket hands out passphrases"
        )

    with subtest("three LUKS2 volumes bound to PCR 16, sharing a passphrase"):
        # All enrolled before PCR 16 is touched, so they seal against the same
        # value and go stale at the same moment.
        format_and_enroll(DEVICE)
        format_and_enroll(DEVICE2)
        format_and_enroll(DEVICE3)

    with subtest("token plugin route: our socket does not disturb a healthy unlock"):
        set_token_plugin(True)
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME}")

        log = watch.new()
        # The plugin unlocks at cryptsetup.c:2691 and returns before the retry
        # loop, so the daemon is legitimately never consulted here. What must
        # hold is the user-visible property: no prompt.
        assert "plain phase" not in log, (
            f"on the token plugin route the new daemon output was:\n{log}\n"
            "expected no 'plain phase' line; its presence means the TPM2 "
            "unlock failed and fell back to a passphrase"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: a healthy TPM2 volume must unlock without prompting"
        )
        machine.succeed(f"systemctl stop {UNIT}")

    with subtest("canary: the zero-byte decline preserves TPM2 unlock on the discovery route"):
        # This is the DESIGN.md section 10 regression test. With the plugin
        # disabled, discover_key() reaches us in the TPM2 phase and everything
        # depends on systemd reading our empty reply as "no key data" rather
        # than as an error.
        set_token_plugin(False)
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME}")

        log = watch.new()
        assert "tpm2 phase, declining with zero bytes" in log, (
            f"on the discovery route the new daemon output was:\n{log}\n"
            "expected a 'tpm2 phase, declining with zero bytes' line, meaning "
            "discover_key() consulted us before the LUKS2 header token"
        )
        assert "plain phase" not in log, (
            f"on the discovery route the new daemon output was:\n{log}\n"
            "expected no 'plain phase' line; its presence means the zero-byte "
            "reply suppressed the LUKS2 header token (DESIGN.md section 10)"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: declining with zero bytes must not cause a prompt"
        )
        machine.succeed(f"systemctl stop {UNIT}")

    with subtest("a broken policy reaches us in the plain phase, and a typo is retried"):
        # Back to the configuration a real machine runs.
        set_token_plugin(True)
        before = header_digest(DEVICE)

        # Extend PCR 16 so the sealed policy no longer matches, for both volumes.
        machine.succeed(
            "tpm2_pcrextend 16:sha256=$(head -c32 /dev/zero | sha256sum | cut -d' ' -f1)"
        )

        watch = LogWatch()
        machine.succeed(f"systemctl start --no-block {UNIT}")
        # Three answers, in the order the daemon asks for them: a typo, the
        # real passphrase, and then a refusal at the consent prompt. The wrong
        # answer must be rejected by us rather than by systemd-cryptsetup --
        # section 2.3 gives us exactly one attempt, and handing back a typo
        # would spend it. Refusing consent keeps this subtest's assertion that
        # the header is untouched.
        machine.succeed(f"answer-passphrase {WRONG} {PASSPHRASE} n")
        machine.wait_for_unit(UNIT)
        machine.succeed(f"test -b /dev/mapper/{VOLUME}")

        log = watch.new()
        assert "plain phase" in log, (
            f"after TPM2 unsealing failed the new daemon output was:\n{log}\n"
            "expected a 'plain phase' line, meaning systemd-cryptsetup fell "
            "back to us for the real passphrase"
        )
        assert re.search(r"passphrase did not unlock .* \(attempt 1 of 3\)", log), (
            f"after answering with a wrong passphrase the new daemon output was:\n{log}\n"
            "expected an 'attempt 1 of 3' line, meaning the wrong passphrase "
            "was caught by validation and re-asked here rather than returned"
        )
        returned = re.findall(r"returned a passphrase of \d+ bytes", log)
        assert len(returned) == 1, (
            f"the new daemon output was:\n{log}\n"
            f"expected exactly one 'returned a passphrase of N bytes' line, got {len(returned)}: "
            "only the validated passphrase may be handed to systemd-cryptsetup"
        )

        assert "re-enrollment was declined" in log, (
            f"after refusing at the consent prompt the new daemon output was:\n{log}\n"
            "expected a 're-enrollment was declined' line"
        )

        after = header_digest(DEVICE)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE} digest was {before} before the "
            f"fallback unlock and {after} after, expected them to be equal: "
            "a declined consent must leave the header exactly as it was "
            "(DESIGN.md section 6)"
        )

    with subtest("a second volume is answered from cache without a second prompt"):
        # DESIGN.md section 5: discovery preempts systemd's keyring cache, so
        # every managed volume asks us first. Remembering the passphrase in
        # process is what keeps the user typing once.
        before = header_digest(DEVICE2)
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT2}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME2}")

        log = watch.new()
        assert "answered from a passphrase seen earlier this boot" in log, (
            f"unlocking the second volume produced:\n{log}\n"
            "expected an 'answered from a passphrase seen earlier this boot' "
            "line, meaning the in-process cache covered it"
        )
        # Section 11 asked whether a refusal should carry across volumes that
        # share a boot state. It does: autotest2 is bound to the same register
        # holding the same value, so the question was already answered and is
        # not asked twice.
        assert "already declined for this boot state" in log, (
            f"unlocking the second volume produced:\n{log}\n"
            "expected an 'already declined for this boot state' line: the "
            "refusal given for the first volume covers this one"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: the second volume must prompt for neither the "
            "passphrase nor consent"
        )

        after = header_digest(DEVICE2)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE2} digest was {before} before the "
            f"fallback unlock and {after} after, expected them to be equal"
        )

    with subtest("the drift verdict names the change in boot measurements"):
        # The daemon was consulted for autotest and autotest2 after PCR 16 was
        # extended out from under their policies, so both must read as drifted
        # -- and the audit line section 6 asks for must name the PCR value that
        # a re-enrollment would seal against.
        log = "\n".join(daemon_log_lines())
        for volume in (VOLUME, VOLUME2):
            expected = (
                f'volume "{volume}": the TPM2 binding has gone stale and can be repaired'
            )
            assert expected in log, (
                f"the daemon output was:\n{log}\n"
                f"expected a {expected!r} line: PCR 16 was extended after "
                "enrollment, so the sealed policy can no longer be satisfied"
            )
        # Section 6 wants the event auditable: what the policy was, what it is
        # becoming, and the measurement behind the change.
        assert re.search(r"can be repaired \(policy [0-9a-f]{16}\.\.\. -> [0-9a-f]{16}\.\.\.\)", log), (
            f"the daemon output was:\n{log}\n"
            "expected the repair line to name both the old and the new policy "
            "digest"
        )
        assert re.search(r'PCR 16 is now [0-9a-f]{64}', log), (
            f"the daemon output was:\n{log}\n"
            "expected a 'PCR 16 is now <sha256>' line recording the state a "
            "re-enrollment would capture"
        )
        assert "lockout counter 0 of" in log, (
            f"the daemon output was:\n{log}\n"
            "expected a 'lockout counter 0 of N' line: a healthy swtpm is not "
            "in dictionary-attack lockout, and reading that is also how the "
            "daemon establishes the TPM answers at all"
        )

    with subtest("a failure that is not drift is not reported as drift"):
        # The pathological case section 4.1's last check exists for: the volume
        # falls back to a passphrase while its sealed policy still matches the
        # PCRs exactly. Re-sealing the very same policy would leave the next
        # boot failing the same way, so the daemon must decline -- and must not
        # reach the consent prompt, since there is nothing to consent to.
        #
        # Manufactured by re-sealing autotest3 against the PCR 16 value that is
        # live right now, then mangling the token's blob so unsealing fails
        # while tpm2-policy-hash and the PCRs stay untouched. (A mangled blob
        # would in fact be repaired by re-enrolling; the check is deliberately
        # conservative and cannot tell that case from one where re-sealing
        # changes nothing. Declining costs a manual repair, guessing costs a
        # header rewrite on every boot forever.)
        #
        # It doubles as the proof that the daemon's trial-session digest really
        # does reproduce what systemd-cryptenroll sealed: the two digests were
        # computed by different code from different directions, and the
        # assertion is that they come out equal.
        machine.succeed(
            f"PASSWORD={PASSPHRASE} {CRYPTENROLL} --wipe-slot=tpm2 "
            f"--tpm2-device=auto --tpm2-pcrs=16 {DEVICE3}"
        )
        mangle_token_blob(DEVICE3)
        before = header_digest(DEVICE3)
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT3}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME3}")

        log = watch.new()
        assert "plain phase" in log, (
            f"unlocking autotest3 produced:\n{log}\n"
            "expected a 'plain phase' line: a token whose blob will not unseal "
            "must fall back to us"
        )
        expected = "the current PCRs still satisfy the enrolled policy"
        assert expected in log, (
            f"unlocking autotest3 produced:\n{log}\n"
            f"expected a {expected!r} line. Its absence means the policy digest "
            "the daemon computed in a TPM trial session does not match the one "
            "systemd-cryptenroll sealed with, for a volume whose PCRs have not "
            "moved at all"
        )
        assert "consent" not in log, (
            f"unlocking autotest3 produced:\n{log}\n"
            "expected no mention of consent: with nothing to repair the user "
            "must not be asked to approve a repair"
        )

        after = header_digest(DEVICE3)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE3} digest was {before} before and "
            f"{after} after, expected them to be equal"
        )
        machine.succeed(f"systemctl stop {UNIT3}")

    with subtest("a drifted PIN enrollment is left alone rather than made TPM-only"):
        # Re-enrolling without the PIN would unlock with the TPM alone, and the
        # verification would happily confirm that.
        machine.succeed(
            f"echo -n {PASSPHRASE} | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --batch-mode {DEVICE4} -"
        )
        machine.succeed(
            f"PASSWORD={PASSPHRASE} NEWPIN={PIN} {CRYPTENROLL} "
            f"--tpm2-device=auto --tpm2-pcrs=16 --tpm2-with-pin=yes {DEVICE4}"
        )
        machine.succeed(
            "tpm2_pcrextend 16:sha256=$(head -c32 /dev/urandom | sha256sum | cut -d' ' -f1)"
        )
        # The correct PIN every time it is asked for, so the TPM2 attempts fail
        # on the policy alone. The token plugin reads it from $PIN; the
        # built-in TPM2 path systemd-cryptsetup falls back to afterwards does
        # not, and prompts once instead.
        pin_dropin = f"/run/systemd/system/{UNIT4}.d"
        machine.succeed(f"mkdir -p {pin_dropin}")
        machine.succeed(
            f"printf '[Service]\\nEnvironment=PIN={PIN}\\n' > {pin_dropin}/pin.conf"
        )
        machine.succeed("systemctl daemon-reload")

        before = header_digest(DEVICE4)
        watch = LogWatch()

        # The PIN is systemd-cryptsetup's prompt; the passphrase comes from our
        # cache, so there is nothing else to answer.
        machine.succeed(f"systemctl start --no-block {UNIT4}")
        machine.succeed(f"answer-passphrase {PIN}")
        machine.wait_until_succeeds(f"test -b /dev/mapper/{VOLUME4}", timeout=120)

        log = watch.new()
        assert "plain phase" in log, (
            f"unlocking the drifted PIN volume produced:\n{log}\n"
            "expected a 'plain phase' line"
        )
        expected = "the enrollment requires a TPM2 PIN, which a repair would silently drop"
        assert expected in log, (
            f"unlocking the drifted PIN volume produced:\n{log}\n"
            f"expected a {expected!r} line"
        )
        assert "can be repaired" not in log, (
            f"unlocking the drifted PIN volume produced:\n{log}\n"
            "expected no 'can be repaired' line"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: a PIN enrollment must not produce a consent prompt"
        )
        after = header_digest(DEVICE4)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE4} digest was {before} before and "
            f"{after} after, expected them to be equal"
        )
        machine.succeed(f"systemctl stop {UNIT4}")
        machine.succeed(f"rm -rf {pin_dropin} && systemctl daemon-reload")

    with subtest("once every configured volume has been served, the daemon exits"):
        # autotest4 was the last of the four to be answered in the plain
        # phase, so the daemon has nothing left to wait for. Its sockets go,
        # and the passphrase cache goes with the process.
        machine.wait_until_fails("systemctl is-active tpm2-autoenrolld.service", timeout=30)
        for volume in (VOLUME, VOLUME2, VOLUME3, VOLUME4):
            machine.fail(f"test -e /run/cryptsetup-keys.d/{volume}.key")
        log = "\n".join(daemon_log_lines())
        expected = "every configured volume is open or has been answered"
        assert expected in log, (
            f"the daemon output was:\n{log}\n"
            f"expected a {expected!r} line explaining why it exited"
        )

    with subtest("the next unlock brings the daemon back, and a public key on the host stops a repair"):
        # systemd-cryptenroll would add a signed policy on its own when it
        # finds one of these, so its presence means the user wants a policy
        # this tool does not produce. autotest3 is drifted by the extend above.
        pem = "/run/systemd/tpm2-pcr-public-key.pem"
        machine.succeed(f"touch {pem}")
        before = header_digest(DEVICE3)
        watch = LogWatch()

        # The drop-in starts a fresh daemon with an empty cache, so the
        # passphrase has to be typed again.
        machine.succeed(f"systemctl start --no-block {UNIT3}")
        machine.succeed(f"answer-passphrase {PASSPHRASE}")
        machine.wait_until_succeeds(f"test -b /dev/mapper/{VOLUME3}", timeout=120)

        state = machine.succeed("systemctl is-active tpm2-autoenrolld.service").strip()
        assert state == "active", (
            f"systemctl is-active tpm2-autoenrolld.service returned {state!r}, "
            "expected 'active': starting a volume must bring the daemon back"
        )

        log = watch.new()
        assert "seen earlier this boot" not in log, (
            f"unlocking autotest3 with a fresh daemon produced:\n{log}\n"
            "expected no cached passphrase: the cache must not outlive the "
            "process that held it"
        )
        expected = f"{pem} exists, so this machine expects a policy this tool does not produce"
        assert expected in log, (
            f"unlocking autotest3 with {pem} present produced:\n{log}\n"
            f"expected a {expected!r} line"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: nothing to consent to"
        )
        after = header_digest(DEVICE3)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE3} digest was {before} before and "
            f"{after} after, expected them to be equal"
        )
        machine.succeed(f"rm {pem}")
        machine.succeed(f"systemctl stop {UNIT3}")

    with subtest("consent accepted: the binding is repaired and verified"):
        # The state machine this tool exists for, end to end. PCR 16 moves
        # again, which both re-breaks autotest3's policy and -- because the
        # consent cache is keyed by boot state -- makes this a question the
        # daemon has not been told the answer to.
        machine.succeed(
            "tpm2_pcrextend 16:sha256=$(head -c32 /dev/urandom | sha256sum | cut -d' ' -f1)"
        )
        before = header_digest(DEVICE3)
        before_token = token_index(DEVICE3)
        watch = LogWatch()

        machine.succeed(f"systemctl start --no-block {UNIT3}")
        # One answer only: the passphrase comes from the cache, so the consent
        # prompt is the only thing asked.
        machine.succeed("answer-passphrase y")
        machine.wait_for_unit(UNIT3)
        machine.succeed(f"test -b /dev/mapper/{VOLUME3}")

        log = watch.new()
        assert "the TPM2 binding has gone stale and can be repaired" in log, (
            f"unlocking autotest3 after the second extend produced:\n{log}\n"
            "expected the preflight to find a repairable binding"
        )
        # Section 4.3 requires the new slot to be checked before it is trusted,
        # by whichever of the two routes is available. On NixOS it is always the
        # second: nixpkgs ships libcryptsetup-token-systemd-tpm2.so in systemd's
        # output rather than in cryptsetup's plugin directory, so the standalone
        # CLI cannot load it and `--token-only` finds no usable token. Accept
        # either, but insist that one of them ran and passed.
        assert re.search(
            r"re-enrolled as token \d+"
            r"( and verified by unsealing it|, and its policy matches the current PCRs)",
            log,
        ), (
            f"unlocking autotest3 after the second extend produced:\n{log}\n"
            "expected a 're-enrolled as token N' line reporting a successful "
            "verification, by unsealing or by policy comparison"
        )

        after = header_digest(DEVICE3)
        assert before != after, (
            f"cryptsetup luksDump {DEVICE3} digest was {before} before and "
            f"{after} after, expected them to differ: consent was given, so "
            "the header must have been rewritten"
        )
        after_token = token_index(DEVICE3)
        assert before_token != after_token, (
            f"the systemd-tpm2 token was at index {before_token} before and "
            f"{after_token} after, expected a different index: --wipe-slot=tpm2 "
            "removes the old token and enrollment adds a new one"
        )

    with subtest("the repaired volume unlocks with no prompt at all"):
        # Section 8's "boot 3", without needing a reboot: PCR 16 has not moved
        # since the re-enrollment, so the freshly sealed policy is satisfied and
        # the volume unlocks silently. This is the assertion that the repair was
        # a real repair rather than a plausible-looking header write.
        machine.succeed(f"systemctl stop {UNIT3}")
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT3}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME3}")

        log = watch.new()
        assert "plain phase" not in log, (
            f"restarting autotest3 after the repair produced:\n{log}\n"
            "expected no 'plain phase' line: the volume should now unseal from "
            "its own token without consulting us for a passphrase"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: a repaired volume must unlock as silently as one "
            "that never drifted"
        )

    with subtest("a volume with no TPM2 token is left alone"):
        # "Never enrolled" rather than "drifted": there is no token to read a
        # PCR selection out of, so creating a binding the user never asked for
        # is not a repair.
        machine.succeed(f"systemctl stop {UNIT3}")
        machine.succeed(f"{CRYPTENROLL} --wipe-slot=tpm2 {DEVICE3}")
        before = header_digest(DEVICE3)
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT3}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME3}")

        log = watch.new()
        expected = "carries no systemd-tpm2 token, so there is no TPM2 binding to repair"
        assert expected in log, (
            f"unlocking a volume with its TPM2 token wiped produced:\n{log}\n"
            f"expected a {expected!r} line"
        )

        after = header_digest(DEVICE3)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE3} digest was {before} before and "
            f"{after} after, expected them to be equal: a volume that was never "
            "TPM2-bound has no binding to repair and must be left exactly as it is"
        )

    with subtest("a header whose selection disagrees with the config is left alone"):
        # The evil-maid case: with offline access to the disk, rewrite the
        # token to name a different PCR and a garbage policy hash. Unsealing
        # fails, the daemon is reached in the plain phase, and the header's
        # word "7" must not become the selection the volume is re-sealed to.
        machine.succeed(f"systemctl stop {UNIT3}")
        machine.succeed(
            f"PASSWORD={PASSPHRASE} {CRYPTENROLL} "
            f"--tpm2-device=auto --tpm2-pcrs=16 {DEVICE3}"
        )

        def tamper(token):
            token["tpm2-pcrs"] = [7]
            token["tpm2-policy-hash"] = "00" * 32

        rewrite_token(DEVICE3, tamper)
        before = header_digest(DEVICE3)
        watch = LogWatch()

        # The passphrase comes from the cache, so a prompt of any kind would
        # leave this start hanging.
        machine.succeed(f"systemctl start {UNIT3}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME3}")

        log = watch.new()
        assert "plain phase" in log, (
            f"unlocking the tampered autotest3 produced:\n{log}\n"
            "expected a 'plain phase' line: a token naming the wrong PCR must "
            "fail to unseal and fall back to us"
        )
        expected = (
            "the header's PCR selection 7 (sha256) differs from the configured 16 (sha256)"
        )
        assert expected in log, (
            f"unlocking the tampered autotest3 produced:\n{log}\n"
            f"expected a {expected!r} line"
        )
        assert "can be repaired" not in log, (
            f"unlocking the tampered autotest3 produced:\n{log}\n"
            "expected no 'can be repaired' line: a selection mismatch must stop "
            "the preflight before the drift check"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: a tampered header must not produce a consent prompt"
        )

        after = header_digest(DEVICE3)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE3} digest was {before} before and "
            f"{after} after, expected them to be equal: a tampered header must "
            "be left exactly as the attacker wrote it"
        )

    with subtest("a peer outside the volume's unit gets nothing, whatever name it binds"):
        # The daemon is up with the passphrase cached: the subtests above were
        # answered from it. The test shell is root but lives in
        # backdoor.service, so binding systemd-cryptsetup's plain-phase name
        # must not be enough to be handed that passphrase.
        spoof = """import socket, sys
    name = sys.argv[1]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("\\0deadbeef/cryptsetup/" + name)
    s.connect("/run/cryptsetup-keys.d/" + name + ".key")
    print(len(s.recv(4096)))
    """.replace("\n    ", "\n")
        machine.succeed(f"cat > /tmp/spoof.py <<'EOF'\n{spoof}EOF")
        watch = LogWatch()

        out = machine.succeed(f"${pkgs.python3}/bin/python3 /tmp/spoof.py {VOLUME3}").strip()
        assert out == "0", (
            f"spoof.py {VOLUME3} read {out} bytes, expected 0: a peer outside "
            "the volume's unit must be declined"
        )
        log = watch.new()
        expected = f"is not in systemd-cryptsetup@{VOLUME3}.service; declining"
        assert expected in log, (
            f"the spoofed connection produced:\n{log}\n"
            f"expected a {expected!r} line"
        )
        assert "returned" not in log, (
            f"the spoofed connection produced:\n{log}\n"
            "expected no 'returned' line: nothing may be written to it"
        )

    with subtest("every volume was paired with the device the config names"):
        # The socket the connection arrived on is what identifies the volume,
        # and the config is what says which device that volume is backed by.
        # That the daemon put those two together correctly is what the rest of
        # this test has been relying on.
        log = "\n".join(daemon_log_lines())
        for volume, device in ((VOLUME, DEVICE), (VOLUME2, DEVICE2), (VOLUME3, DEVICE3)):
            expected = f'serving volume "{volume}" on {device}'
            assert expected in log, (
                f"the daemon output was:\n{log}\n"
                f"expected a {expected!r} line at startup"
            )

    with subtest("the volumes are usable"):
        machine.succeed(f"mkfs.ext4 /dev/mapper/{VOLUME}")
        machine.succeed(f"mkfs.ext4 /dev/mapper/{VOLUME2}")
        machine.succeed(f"mkfs.ext4 /dev/mapper/{VOLUME3}")
        machine.succeed(f"systemctl stop {UNIT} {UNIT2} {UNIT3}")

    with subtest("stopping the daemon takes its sockets out of the way"):
        # /run survives switch-root, so a socket left behind here is one stage
        # 2's systemd-cryptsetup would find and connect to with nobody on the
        # other end. The daemon unlinks them when it is asked to stop.
        machine.succeed("systemctl stop tpm2-autoenrolld.service")
        for volume in (VOLUME, VOLUME2, VOLUME3):
            machine.fail(f"test -e /run/cryptsetup-keys.d/{volume}.key")
  '';
}
