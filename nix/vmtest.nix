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
  };

  daemonConfig = {
    volumes = builtins.mapAttrs
      (_: device: {
        inherit device;
        tpm2Device = "auto";
        tpm2Pcrs = [ 16 ];
        enrollIfAbsent = false;
      })
      volumes;
  };

  # A minimal password agent, which is all the test needs to stand in for
  # plymouth or the console agent. systemd's protocol is: read Socket= out of
  # /run/systemd/ask-password/ask.*, then send "+" followed by the password as a
  # datagram. This is what a real agent does, so nothing here is a hook into the
  # daemon.
  #
  # It takes a sequence of answers and spends one per *distinct* request, which
  # is what lets a test say "answer wrong, then right" and assert that the
  # daemon asked twice.
  answerPassphrase = pkgs.writeScriptBin "answer-passphrase" ''
    #!${pkgs.python3}/bin/python3
    import glob
    import os
    import socket
    import sys
    import time

    ANSWERS = sys.argv[1:]
    if not ANSWERS:
        print("usage: answer-passphrase ANSWER [ANSWER...]", file=sys.stderr)
        sys.exit(2)


    def reply_socket(ask_file):
        try:
            with open(ask_file) as fh:
                for line in fh:
                    if line.startswith("Socket="):
                        return line.split("=", 1)[1].strip()
        except FileNotFoundError:
            pass
        return None


    def answer_one(answer, already):
        """Spend one answer on the first request we have not already answered."""
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for ask_file in sorted(glob.glob("/run/systemd/ask-password/ask.*")):
                if ask_file in already:
                    continue
                path = reply_socket(ask_file)
                if not path or not os.path.exists(path):
                    continue
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    sock.connect(path)
                    sock.send(b"+" + answer.encode())
                finally:
                    sock.close()
                already.add(ask_file)
                print("answered " + ask_file)
                return True
            time.sleep(0.1)
        return False


    answered = set()
    for index, answer in enumerate(ANSWERS):
        if not answer_one(answer, answered):
            print(
                f"request {index + 1} of {len(ANSWERS)} did not appear within 60s",
                file=sys.stderr,
            )
            sys.exit(1)
    sys.exit(0)
  '';
in
pkgs.testers.runNixOSTest {
  name = "tpm2-autoenroll-socket-core";

  nodes.machine = { lib, pkgs, ... }: {
    virtualisation.tpm.enable = true;
    virtualisation.emptyDiskImages = [ 512 512 512 ];
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

    # The daemon's own configuration: which volumes it may act on, and the
    # backing device behind each (DESIGN.md section 7.1). Without an entry a
    # volume's connections are declined, so this file is what turns the socket
    # from inert into useful.
    environment.etc."tpm2-autoenroll/config.json".text = builtins.toJSON daemonConfig;

    systemd.tmpfiles.rules = [
      "d /run/cryptsetup-keys.d 0700 root root -"
    ];

    systemd.sockets.tpm2-autoenrolld = {
      description = "TPM2 auto-enrollment key socket";
      wantedBy = [ "sockets.target" ];
      before = [ "cryptsetup-pre.target" ];
      unitConfig.DefaultDependencies = "no";
      socketConfig = {
        ListenStream = lib.mapAttrsToList
          (volume: _: "/run/cryptsetup-keys.d/${volume}.key")
          volumes;
        Accept = "no";
        SocketMode = "0600";
      };
    };

    systemd.services.tpm2-autoenrolld = {
      description = "TPM2 auto-enrollment daemon";
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "exec";
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


    def mangle_token_blob(device):
        """Break unsealing without touching the policy or the PCRs.

        The sealed blob is what the TPM hands back a key from; replacing it with
        something that is still valid base64 but is not a TPM object makes every
        unseal attempt fail, while tpm2-policy-hash -- the thing the daemon
        compares against -- stays exactly as enrolled."""
        import json

        token = json.loads(
            machine.succeed(f"cryptsetup token export --token-id 0 {device}")
        )

        def flatten(value):
            # systemd writes this either as one base64 string or as an array of
            # them (key sharding); both spellings are live.
            core = value.rstrip("=")
            return "A" * len(core) + value[len(core):]

        blob = token["tpm2-blob"]
        token["tpm2-blob"] = (
            [flatten(b) for b in blob] if isinstance(blob, list) else flatten(blob)
        )

        machine.succeed(f"cryptsetup token remove --token-id 0 {device}")
        machine.succeed(
            f"cat > /tmp/token.json <<'EOF'\n{json.dumps(token)}\nEOF"
        )
        machine.succeed(
            f"cryptsetup token import --token-id 0 --json-file /tmp/token.json {device}"
        )


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
    machine.wait_for_unit("tpm2-autoenrolld.socket")
    machine.succeed(f"test -S /run/cryptsetup-keys.d/{VOLUME}.key")
    machine.succeed(f"test -S /run/cryptsetup-keys.d/{VOLUME2}.key")

    with subtest("two LUKS2 volumes bound to PCR 16, sharing a passphrase"):
        # Both are enrolled before PCR 16 is touched, so both seal against the
        # same value and both go stale at the same moment.
        format_and_enroll(DEVICE)
        format_and_enroll(DEVICE2)

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
        # The wrong answer must be rejected by us, not by systemd-cryptsetup:
        # section 2.3 gives us exactly one attempt, and handing back a typo
        # would spend it.
        machine.succeed(f"answer-passphrase {WRONG} {PASSPHRASE}")
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

        after = header_digest(DEVICE)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE} digest was {before} before the "
            f"fallback unlock and {after} after, expected them to be equal: "
            "this slice must not touch the LUKS header"
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
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: the second volume must not prompt again"
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
            expected = f'volume "{volume}": token 0: the boot measurements have changed'
            assert expected in log, (
                f"the daemon output was:\n{log}\n"
                f"expected a {expected!r} line: PCR 16 was extended after "
                "enrollment, so the sealed policy can no longer be satisfied"
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
        # boot failing the same way, so the daemon must not read this as drift.
        #
        # Manufactured by mangling the token's sealed blob, which makes
        # unsealing fail while leaving tpm2-policy-hash and the PCRs alone.
        # (A mangled blob would in fact be repaired by re-enrolling; the check
        # is deliberately conservative and cannot tell that case apart from one
        # where re-sealing changes nothing. Declining costs a manual repair,
        # guessing costs a header rewrite on every boot.)
        #
        # It doubles as the proof that the daemon's trial-session digest really
        # does reproduce what systemd-cryptenroll sealed: the two digests were
        # computed by different code from different directions, and the
        # assertion is that they come out equal.
        format_and_enroll(DEVICE3)
        mangle_token_blob(DEVICE3)
        before = header_digest(DEVICE3)
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT3}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME3}")

        log = watch.new()
        assert "plain phase" in log, (
            f"unlocking autotest3 produced:\n{log}\n"
            "expected a 'plain phase' line: with tpm2-device pointing at a "
            "device that does not exist, systemd-cryptsetup must fall back to us"
        )
        expected = "the current PCRs still satisfy the enrolled policy"
        assert expected in log, (
            f"unlocking autotest3 produced:\n{log}\n"
            f"expected a {expected!r} line. Its absence means the policy digest "
            "the daemon computed in a TPM trial session does not match the one "
            "systemd-cryptenroll sealed with, for a volume whose PCRs have not "
            "moved at all"
        )
        assert "the boot measurements have changed" not in log, (
            f"unlocking autotest3 produced:\n{log}\n"
            "expected no drift line: this volume's PCRs are exactly what it was "
            "enrolled against"
        )

        after = header_digest(DEVICE3)
        assert before == after, (
            f"cryptsetup luksDump {DEVICE3} digest was {before} before and "
            f"{after} after, expected them to be equal"
        )

    with subtest("a volume with no TPM2 token is left alone"):
        # "Never enrolled" rather than "drifted". Re-enrolling here would be
        # creating a binding the user never asked for, which is what
        # enrollIfAbsent exists to gate.
        machine.succeed(f"systemctl stop {UNIT3}")
        machine.succeed(f"{CRYPTENROLL} --wipe-slot=tpm2 {DEVICE3}")
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT3}")
        machine.succeed(f"test -b /dev/mapper/{VOLUME3}")

        log = watch.new()
        expected = "carries no systemd-tpm2 token, so there is no TPM2 binding to repair"
        assert expected in log, (
            f"unlocking a volume with its TPM2 token wiped produced:\n{log}\n"
            f"expected a {expected!r} line"
        )

    with subtest("both sockets were matched to their configuration at startup"):
        # A socket with no config entry has no backing device to validate
        # against, so it declines everything. That the daemon paired each
        # listener with the right device is what the rest of this test has been
        # relying on.
        log = "\n".join(daemon_log_lines())
        for volume, device in ((VOLUME, DEVICE), (VOLUME2, DEVICE2)):
            expected = f'serving volume "{volume}" on {device}'
            assert expected in log, (
                f"the daemon output was:\n{log}\n"
                f"expected a {expected!r} line at startup"
            )

    with subtest("the volumes are usable"):
        machine.succeed(f"mkfs.ext4 /dev/mapper/{VOLUME}")
        machine.succeed(f"mkfs.ext4 /dev/mapper/{VOLUME2}")
        machine.succeed(f"systemctl stop {UNIT} {UNIT2}")
  '';
}
