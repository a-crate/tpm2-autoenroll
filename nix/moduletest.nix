# What the NixOS module adds, as opposed to what the daemon does.
#
# vmtest.nix hand-writes the unit and then exercises the daemon's state machine
# through it. This test writes no units at all: everything the machine runs
# comes from `services.tpm2-autoenroll`, so what is under test is the module's
# half of the contract.
#
# Assertions, in order of importance:
#
#   1. The daemon is running, with its sockets bound, before the volume it
#      serves is unlocked -- without the test arranging either. That is the
#      module's central job, and it rests on two things: the drop-in that puts
#      Wants=/After= on every systemd-cryptsetup@ instance, and Type=notify,
#      which is what makes "after" mean "after the sockets exist" rather than
#      "after the binary was exec'd".
#   2. The daemon manages exactly the TPM2-bound volumes of the crypttab it
#      finds, less anything in services.tpm2-autoenroll.ignore. Nothing in this
#      configuration lists a volume.
#   3. A healthy boot is undisturbed: the token plugin unlocks the volume and
#      the daemon never says a word.
#   4. The generated wiring actually carries a repair end to end, so a passing
#      module test is not merely a passing unit-file diff.
#
# stages = [ "systemd" ] puts the units in stage 2 where the test can drive
# them; the initrd path differs only in where the same unit and drop-in are
# written.
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
        512
      ];
      virtualisation.memorySize = 2048;

      environment.systemPackages = [
        pkgs.cryptsetup
        pkgs.tpm2-tools
        answerPassphrase
      ];

      # The whole of the machine's volume configuration, and the module never
      # reads it: the daemon does, at startup, in the stage it is running in.
      #
      # Field 3 is "-": no key file, which is what makes systemd-cryptsetup set
      # try_discover_key and consult the daemon's socket. noauto keeps the
      # unlock under the test's control rather than under boot ordering.
      #
      # modtest2 names its TPM by path rather than "auto", so the daemon is
      # shown taking that from the crypttab as well.
      environment.etc.crypttab.text = ''
        modtest /dev/vdb - noauto,tpm2-device=auto
        modtest2 /dev/vdc - noauto,tpm2-device=/dev/tpmrm0
        modtest3 /dev/vdd - noauto,tpm2-device=auto
      '';

      services.tpm2-autoenroll = {
        enable = true;
        package = tpm2-autoenrolld;
        stages = [ "systemd" ];
        ignore = [ "modtest3" ];
      };
    };

  testScript = ''
    PASSPHRASE = ${builtins.toJSON passphrase}
    CRYPTENROLL = "${pkgs.systemd}/bin/systemd-cryptenroll"
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

    with subtest("the module writes the ignore list the daemon reads"):
        actual = machine.succeed("cat /etc/tpm2-autoenroll/ignore")
        assert actual == "modtest3\n", (
            f"/etc/tpm2-autoenroll/ignore contained {actual!r}, expected "
            "'modtest3\\n': one entry per line at the path the daemon defaults to"
        )

    with subtest("nothing is running before a volume needs it"):
        # The daemon is pulled in by the systemd-cryptsetup@ instances rather
        # than by a target, so on a machine where nothing has been unlocked yet
        # it has no reason to exist.
        state = machine.succeed(f"systemctl is-active {SERVICE} || true").strip()
        assert state == "inactive", (
            f"systemctl is-active {SERVICE} returned {state!r}, expected "
            "'inactive': the daemon is pulled in by the volumes it serves"
        )
        machine.fail("test -e /run/cryptsetup-keys.d")

    with subtest("the drop-in orders every cryptsetup instance after the daemon"):
        # The module never names a volume, so this has to hold for instances it
        # has never heard of. Checking the property on the unit is what says the
        # drop-in landed on the template rather than on one instance.
        after = machine.succeed(f"systemctl show -p After --value {UNIT}").split()
        assert SERVICE in after, (
            f"systemctl show -p After --value {UNIT} returned {after}, expected "
            f"it to contain {SERVICE!r}: the drop-in is what makes the daemon "
            "start first"
        )

    with subtest("two LUKS2 volumes bound to PCR 16"):
        format_and_enroll("/dev/vdb")
        format_and_enroll("/dev/vdc")

    with subtest("starting a volume pulls the daemon up first"):
        # Nothing here starts the daemon: the Wants= in the drop-in does, and
        # the After= is what makes "first" true. If either were missing,
        # discover_key() would find no socket and the volume would still unlock
        # -- silently losing the feature -- so the assertions below are on the
        # daemon, not on the volume.
        watch = LogWatch()
        machine.succeed(f"systemctl start {UNIT}")
        machine.succeed("test -b /dev/mapper/modtest")

        state = machine.succeed(f"systemctl is-active {SERVICE}").strip()
        assert state == "active", (
            f"systemctl is-active {SERVICE} returned {state!r} after starting "
            f"{UNIT}, expected 'active': the daemon must be pulled in by the "
            "volume it serves"
        )

        # The daemon creates its own directory; there is no tmpfiles.d entry
        # whose ordering in the initrd we would otherwise have to prove.
        mode = machine.succeed("stat -c %a /run/cryptsetup-keys.d").strip()
        assert mode == "700", (
            f"stat -c %a /run/cryptsetup-keys.d returned {mode!r}, expected '700'"
        )
        for volume in ("modtest", "modtest2"):
            machine.succeed(f"test -S /run/cryptsetup-keys.d/{volume}.key")
        mode = machine.succeed("stat -c %a /run/cryptsetup-keys.d/modtest.key").strip()
        assert mode == "600", (
            f"stat -c %a /run/cryptsetup-keys.d/modtest.key returned {mode!r}, "
            "expected '600'"
        )

        # services.tpm2-autoenroll.ignore, end to end: modtest3 is TPM2-bound in
        # the same crypttab as the other two and still gets no socket, so it can
        # never be prompted for or re-enrolled.
        machine.fail("test -e /run/cryptsetup-keys.d/modtest3.key")

        log = "\n".join(daemon_log_lines())
        for volume, device in (("modtest", "/dev/vdb"), ("modtest2", "/dev/vdc")):
            expected = f'serving volume "{volume}" on {device}'
            assert expected in log, (
                f"the daemon output was:\n{log}\n"
                f"expected a {expected!r} line: the daemon's whole view of the "
                "machine comes from the crypttab"
            )

        # 2.4: with the token plugin present the volume unseals from its header
        # before the retry loop runs, so the daemon is started but never
        # consulted. That is the cheapest the happy path can be while still
        # guaranteeing the socket is in place before the unlock.
        assert "plain phase" not in watch.new(), (
            f"a healthy TPM2 unlock produced:\n{watch.new()}\n"
            "expected no 'plain phase' line: the token plugin returns before "
            "discover_key() runs, so nothing should have connected to us"
        )
        pending = pending_password_requests()
        assert pending == "", (
            f"pending_password_requests() returned {pending!r}, expected an "
            "empty string: a healthy TPM2 volume must unlock without prompting"
        )
        machine.succeed(f"systemctl stop {UNIT}")

    with subtest("a drifted volume is repaired through the generated wiring"):
        # End to end over the module's units: nothing in this subtest knows
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
