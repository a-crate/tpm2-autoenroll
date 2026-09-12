# Tier-1 canary test (DESIGN.md section 8).
#
# The claim under test is the one DESIGN.md section 10 flags as load-bearing and
# undocumented: replying to the TPM2-phase connection with zero bytes leaves
# `iovec_is_set(key_data)` false, so the dispatch at cryptsetup.c:2044 falls
# through to the LUKS2 header token and ordinary TPM2 unlocking still works.
#
# Two assertions, in order of importance:
#
#   1. With the daemon's socket installed and the PCR policy satisfied, the
#      volume unlocks silently. If this breaks, every managed volume prompts on
#      every boot and the tool is worthless -- so this is the regression test to
#      run first against any new systemd.
#   2. With the policy broken, the daemon is reached in the plain phase and the
#      passphrase it returns activates the volume.
#
# PCR 16 is the debug PCR: extendable from userspace, which lets us manufacture
# the policy mismatch in place. No reboot and no boot loader, so the test is
# fast enough to gate CI. The volume is unlocked from the booted system rather
# than the initrd, which section 9.1 says is the same code path.
{ pkgs, tpm2-autoenrolld }:

let
  passphrase = "correct-horse-battery-staple";
  volume = "autotest";
  device = "/dev/vdb";

  # A minimal password agent, which is all the test needs to stand in for
  # plymouth or the console agent. systemd's protocol is: read Socket= out of
  # /run/systemd/ask-password/ask.*, then send "+" followed by the password as a
  # datagram. This is what a real agent does, so nothing here is a hook into the
  # daemon.
  answerPassphrase = pkgs.writeScriptBin "answer-passphrase" ''
    #!${pkgs.python3}/bin/python3
    import glob
    import os
    import socket
    import sys
    import time

    PASSPHRASE = ${builtins.toJSON passphrase}
    DEADLINE = time.monotonic() + 60


    def reply_socket(ask_file):
        try:
            with open(ask_file) as fh:
                for line in fh:
                    if line.startswith("Socket="):
                        return line.split("=", 1)[1].strip()
        except FileNotFoundError:
            pass
        return None


    while time.monotonic() < DEADLINE:
        for ask_file in glob.glob("/run/systemd/ask-password/ask.*"):
            path = reply_socket(ask_file)
            if not path or not os.path.exists(path):
                continue
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                sock.connect(path)
                sock.send(b"+" + PASSPHRASE.encode())
            finally:
                sock.close()
            print("answered " + ask_file)
            sys.exit(0)
        time.sleep(0.1)

    print("no password request appeared within 60s", file=sys.stderr)
    sys.exit(1)
  '';
in
pkgs.testers.runNixOSTest {
  name = "tpm2-autoenroll-socket-core";

  nodes.machine = { lib, pkgs, ... }: {
    virtualisation.tpm.enable = true;
    virtualisation.emptyDiskImages = [ 512 ];
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
    environment.etc.crypttab.text = ''
      ${volume} ${device} - noauto,tpm2-device=auto
    '';

    systemd.tmpfiles.rules = [
      "d /run/cryptsetup-keys.d 0700 root root -"
    ];

    systemd.sockets.tpm2-autoenrolld = {
      description = "TPM2 auto-enrollment key socket";
      wantedBy = [ "sockets.target" ];
      before = [ "cryptsetup-pre.target" ];
      unitConfig.DefaultDependencies = "no";
      socketConfig = {
        ListenStream = "/run/cryptsetup-keys.d/${volume}.key";
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
    VOLUME = ${builtins.toJSON volume}
    DEVICE = ${builtins.toJSON device}
    UNIT = f"systemd-cryptsetup@{VOLUME}.service"
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


    def header_digest():
        return machine.succeed(f"cryptsetup luksDump {DEVICE} | sha256sum").split()[0]


    def pending_password_requests():
        return machine.succeed(
            "ls /run/systemd/ask-password/ 2>/dev/null | grep '^ask\\.' || true"
        ).strip()


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

    with subtest("a LUKS2 volume bound to PCR 16"):
        # pbkdf2 with few iterations: argon2id would spend seconds and a
        # gigabyte per unlock, and the KDF is not what is under test here.
        machine.succeed(
            f"echo -n {PASSPHRASE} | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --batch-mode {DEVICE} -"
        )
        machine.succeed(
            f"PASSWORD={PASSPHRASE} {CRYPTENROLL} "
            f"--tpm2-device=auto --tpm2-pcrs=16 {DEVICE}"
        )
        machine.succeed(f"cryptsetup luksDump {DEVICE} | grep -q systemd-tpm2")

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

    with subtest("a broken policy reaches us in the plain phase"):
        # Back to the configuration a real machine runs.
        set_token_plugin(True)
        before = header_digest()

        # Extend PCR 16 so the sealed policy no longer matches.
        machine.succeed(
            "tpm2_pcrextend 16:sha256=$(head -c32 /dev/zero | sha256sum | cut -d' ' -f1)"
        )

        watch = LogWatch()
        machine.succeed(f"systemctl start --no-block {UNIT}")
        machine.succeed("answer-passphrase")
        machine.wait_for_unit(UNIT)
        machine.succeed(f"test -b /dev/mapper/{VOLUME}")

        log = watch.new()
        assert "plain phase" in log, (
            f"after TPM2 unsealing failed the new daemon output was:\n{log}\n"
            "expected a 'plain phase' line, meaning systemd-cryptsetup fell "
            "back to us for the real passphrase"
        )
        assert re.search(r"returned a passphrase of \d+ bytes", log), (
            f"after answering the prompt the new daemon output was:\n{log}\n"
            "expected a 'returned a passphrase of N bytes' line"
        )

        after = header_digest()
        assert before == after, (
            f"cryptsetup luksDump {DEVICE} digest was {before} before the "
            f"fallback unlock and {after} after, expected them to be equal: "
            "this slice must not touch the LUKS header"
        )

    with subtest("the volume is usable"):
        machine.succeed(f"mkfs.ext4 /dev/mapper/{VOLUME}")
        machine.succeed(f"systemctl stop {UNIT}")
  '';
}
