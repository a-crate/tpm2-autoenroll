# Builds the daemon with the systemd-cryptsetup it should expect on the other
# end of a key socket baked in (src/peer.rs).
#
# Resolved in the builder rather than during evaluation. nixpkgs wraps
# systemd-cryptsetup to put its libcryptsetup token plugins on
# LD_LIBRARY_PATH, so bin/systemd-cryptsetup is a stub that execs a .-wrapped
# sibling, and it is the sibling that /proc/<pid>/exe names. Picking between
# them with builtins.pathExists would force systemd to be realised during
# evaluation, which `nix flake check --no-build` and a dry-run rebuild should
# not have to do. The builder already has it.
{
  package,
  systemdPackage,
}:

package.overrideAttrs (old: {
  preConfigure = (old.preConfigure or "") + ''
    expectedPeer=${systemdPackage}/bin/systemd-cryptsetup
    if [ -e ${systemdPackage}/bin/.systemd-cryptsetup-wrapped ]; then
      expectedPeer=${systemdPackage}/bin/.systemd-cryptsetup-wrapped
    fi
    # A mismatch here costs the passphrase path and says so only in the
    # journal at boot, so leave the choice in the build log.
    echo "expecting key-socket peers to run $expectedPeer"
    export TPM2_AUTOENROLL_SYSTEMD_CRYPTSETUP="$expectedPeer"
  '';
})
