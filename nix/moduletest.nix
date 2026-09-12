# What the NixOS module adds, as opposed to what the daemon does.
#
# vmtest.nix hand-writes the units and the config file and then exercises the
# daemon's state machine through them. This test writes neither: everything the
# machine runs comes from `services.tpm2-autoenroll`, so what is under test is
# the module's half of the contract -- that the units it generates are wired
# into systemd correctly, and that the config file it writes is the one the
# daemon reads.
#
# Assertions, in order of importance:
#
#   1. The socket is listening before the volume it serves is unlocked, without
#      the test arranging that. This is the module's central job and the one
#      DESIGN.md section 3.1 had wrong: ordering against cryptsetup-pre.target
#      alone is inert, because that target carries RefuseManualStart and is only
#      pulled in by the cryptsetup generator.
#   2. /run/cryptsetup-keys.d exists with the right mode, created by
#      DirectoryMode= rather than by a tmpfiles.d entry.
#   3. The config file's contents are the module's globals merged with each
#      volume's overrides, which is what lets the daemon treat its schema as a
#      flat read (7.1).
#   4. Nothing runs until something needs it: on a healthy boot the token plugin
#      unlocks the volume and the daemon is never started at all (2.4).
#   5. The generated wiring actually carries a repair end to end, so a passing
#      module test is not merely a passing unit-file diff.
#
# The volumes are at stage = "system", so the units land in stage 2 where the
# test can drive them; the initrd path differs only in where the same two units
# are written.
{
  pkgs,
  tpm2-autoenroll-module,
  tpm2-autoenrolld,
}:

let
  passphrase = "correct-horse-battery-staple";

  answerPassphrase = import ./answer-passphrase.nix { inherit pkgs; };
in
pkgs.testers.runNixOSTest {
  name = "tpm2-autoenroll-module";

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [ tpm2-autoenroll-module ];

      virtualisation.tpm.enable = true;
      virtualisation.emptyDiskImages = [
        512
        512
      ];
      virtualisation.memorySize = 2048;

      environment.systemPackages = [
        pkgs.cryptsetup
        pkgs.tpm2-tools
        answerPassphrase
      ];

      # Field 3 is "-": no key file, which is what makes systemd-cryptsetup set
      # try_discover_key and consult the module's socket (2.2). noauto keeps the
      # unlock under the test's control rather than under boot ordering.
      #
      # NixOS has no first-class option for stage-2 crypttab the way it has
      # boot.initrd.luks.devices for stage 1, so this is written by hand. It is
      # the only part of the machine's configuration that is.
      environment.etc.crypttab.text = ''
        modtest /dev/vdb - noauto,tpm2-device=auto
        modtest2 /dev/vdc - noauto,tpm2-device=auto
      '';

      services.tpm2-autoenroll = {
        enable = true;
        package = tpm2-autoenrolld;

        # PCR 16 is the debug PCR, resettable from userspace, which is how the
        # policy mismatch is manufactured without a reboot.
        tpm2Pcrs = [ 16 ];

        volumes.modtest = {
          device = "/dev/vdb";
          stage = "system";
        };

        # Overrides on every field that has one, so the merge in 7.1 is visible
        # in the file rather than merely asserted to happen.
        volumes.modtest2 = {
          device = "/dev/vdc";
          stage = "system";
          tpm2Device = "/dev/tpmrm0";
          tpm2Pcrs = [
            16
            7
          ];
          enrollIfAbsent = true;
        };
      };
    };

  testScript = ''
    import json

    PASSPHRASE = ${builtins.toJSON passphrase}
    CRYPTENROLL = "${pkgs.systemd}/bin/systemd-cryptenroll"
    SOCKET = "tpm2-autoenrolld.socket"
    SERVICE = "tpm2-autoenrolld.service"
    UNIT = "systemd-cryptsetup@modtest.service"


    def daemon_log_lines():
        out = machine.succeed(
            f"journalctl -u {SERVICE} --no-pager -o cat || true"
        )
        return out.splitlines()


    class LogWatch:
        """Only look at daemon output produced after the watch was taken."""

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
        machine.succeed(
            f"echo -n {PASSPHRASE} | cryptsetup luksFormat --type luks2 "
            f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --batch-mode {device} -"
        )
        machine.succeed(
            f"PASSWORD={PASSPHRASE} {CRYPTENROLL} "
            f"--tpm2-device=auto --tpm2-pcrs=16 {device}"
        )


    machine.wait_for_unit("multi-user.target")
    machine.wait_for_file("/dev/tpmrm0")

    with subtest("the module writes the config file the daemon expects"):
        # Both halves of 7.1's contract in one assertion: the path the daemon
        # defaults to, and per-volume values already merged with the globals so
        # that config.rs never has to know what a default is.
        actual = json.loads(machine.succeed("cat /etc/tpm2-autoenroll/config.json"))
        expected = {
            "volumes": {
                "modtest": {
                    "device": "/dev/vdb",
                    "tpm2Device": "auto",
                    "tpm2Pcrs": [16],
                    "enrollIfAbsent": False,
                },
                "modtest2": {
                    "device": "/dev/vdc",
                    "tpm2Device": "/dev/tpmrm0",
                    "tpm2Pcrs": [16, 7],
                    "enrollIfAbsent": True,
                },
            }
        }
        assert actual == expected, (
            f"/etc/tpm2-autoenroll/config.json contained {actual}, expected "
            f"{expected}: modtest takes every global, modtest2 overrides each "
            "one, and both must arrive at the daemon already resolved"
        )

    with subtest("nothing is running before a volume needs it"):
        # The socket is wanted by the systemd-cryptsetup@ units rather than by
        # sockets.target, so on a machine where nothing has been unlocked yet
        # neither unit has any reason to exist.
        state = machine.succeed(f"systemctl is-active {SOCKET} || true").strip()
        assert state == "inactive", (
            f"systemctl is-active {SOCKET} returned {state!r}, expected "
            "'inactive': the socket is pulled in by the volumes it serves, not "
            "by sockets.target"
        )
        machine.fail("test -e /run/cryptsetup-keys.d")

    with subtest("two LUKS2 volumes bound to PCR 16"):
        format_and_enroll("/dev/vdb")
        format_and_enroll("/dev/vdc")

    with subtest("starting a volume pulls the socket up first"):
        # The module's central claim. Nothing here starts the socket: the
        # [Install] WantedBy on systemd-cryptsetup@modtest.service does, and the
        # Before= on the same unit is what makes "first" true. If either were
        # missing, discover_key() would find no socket and the volume would
        # still unlock -- silently losing the feature -- so the assertions below
        # are on the socket, not on the volume.
        watch = LogWatch()
        machine.succeed(f"systemctl start {UNIT}")
        machine.succeed("test -b /dev/mapper/modtest")

        state = machine.succeed(f"systemctl is-active {SOCKET}").strip()
        assert state == "active", (
            f"systemctl is-active {SOCKET} returned {state!r} after starting "
            f"{UNIT}, expected 'active': the socket must be pulled in by the "
            "volume it serves"
        )

        # DirectoryMode= in place of the tmpfiles.d entry DESIGN.md 3.1 called
        # for. systemd.socket(5) creates a ListenStream= path's parent
        # directories, and this is the setting that decides their mode.
        mode = machine.succeed("stat -c %a /run/cryptsetup-keys.d").strip()
        assert mode == "700", (
            f"stat -c %a /run/cryptsetup-keys.d returned {mode!r}, expected "
            "'700' from DirectoryMode="
        )
        for volume in ("modtest", "modtest2"):
            machine.succeed(f"test -S /run/cryptsetup-keys.d/{volume}.key")
        mode = machine.succeed("stat -c %a /run/cryptsetup-keys.d/modtest.key").strip()
        assert mode == "600", (
            f"stat -c %a /run/cryptsetup-keys.d/modtest.key returned {mode!r}, "
            "expected '600' from SocketMode="
        )

        # 2.4: with the token plugin present the volume unseals from its header
        # before the retry loop runs, so the daemon is not merely silent here --
        # it was never started. That is the cheapest possible cost on the happy
        # path, and it is a property of the socket being activation-triggered.
        state = machine.succeed(f"systemctl is-active {SERVICE} || true").strip()
        assert state == "inactive", (
            f"systemctl is-active {SERVICE} returned {state!r} after a healthy "
            "TPM2 unlock, expected 'inactive': the token plugin returns before "
            "discover_key() runs, so nothing should have connected to us"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: a healthy TPM2 volume must unlock without prompting"
        )
        assert watch.new() == "", (
            "the daemon logged output during a healthy unlock, expected none"
        )
        machine.succeed(f"systemctl stop {UNIT}")

    with subtest("a drifted volume is repaired through the generated units"):
        # End to end over the module's wiring: nothing in this subtest knows
        # where the socket is or how the daemon was configured.
        machine.succeed(
            "tpm2_pcrextend 16:sha256=$(head -c32 /dev/urandom | sha256sum | cut -d' ' -f1)"
        )
        before = header_digest("/dev/vdb")
        watch = LogWatch()

        machine.succeed(f"systemctl start --no-block {UNIT}")
        # The passphrase, then consent. Two prompts, in that order: consent is
        # asked only after the passphrase has been validated (3.3).
        machine.succeed(f"answer-passphrase {PASSPHRASE} y")
        machine.wait_for_unit(UNIT)
        machine.succeed("test -b /dev/mapper/modtest")

        log = watch.new()
        assert 'serving volume "modtest" on /dev/vdb' in log, (
            f"the daemon output was:\n{log}\n"
            "expected a 'serving volume \"modtest\" on /dev/vdb' line: the "
            "listening socket's path and the module's config file have to name "
            "the same volume for either to be useful"
        )
        assert "the TPM2 binding has gone stale and can be repaired" in log, (
            f"the daemon output was:\n{log}\n"
            "expected the preflight to find a repairable binding after PCR 16 "
            "moved"
        )

        after = header_digest("/dev/vdb")
        assert before != after, (
            f"cryptsetup luksDump /dev/vdb digest was {before} before and "
            f"{after} after, expected them to differ: consent was given, so the "
            "header must have been rewritten"
        )

    with subtest("the repaired volume unlocks silently"):
        # PCR 16 has not moved since the repair, so the freshly sealed policy is
        # satisfied. This is what distinguishes a real repair from a
        # plausible-looking header write.
        machine.succeed(f"systemctl stop {UNIT}")
        watch = LogWatch()

        machine.succeed(f"systemctl start {UNIT}")
        machine.succeed("test -b /dev/mapper/modtest")

        log = watch.new()
        assert "plain phase" not in log, (
            f"restarting modtest after the repair produced:\n{log}\n"
            "expected no 'plain phase' line: the volume should unseal from its "
            "own token without consulting us for a passphrase"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: a repaired volume must unlock as silently as one "
            "that never drifted"
        )
        machine.succeed(f"systemctl stop {UNIT}")
  '';
}
