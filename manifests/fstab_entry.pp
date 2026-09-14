# @summary
#    Ensure exactly one fstab entry exists for a mountpoint
#
# Replaces every existing entry for a mountpoint with a single canonical entry.
# Installers do not agree on how to name a device - Ubuntu's curtin writes
# "/dev/disk/by-uuid/<uuid>" while the Red Hat and Debian installers write
# "UUID=<uuid>" - so a rule matching on the device name alone can append a
# second entry for a mountpoint that is already listed. Addressing the entry by
# its mountpoint through the Augeas fstab lens removes any such duplicates.
#
# @param mountpoint
#    Mountpoint the entry is for, the second field of the fstab entry.
#
# @param spec
#    Device to mount, the first field of the fstab entry, e. g. "UUID=BC04-FDA2".
#
# @param fstype
#    Filesystem type, the third field of the fstab entry.
#
# @param mountoptions
#    Mount options, the fourth field of the fstab entry.
#
# @param dump
#    Dump frequency, the fifth field of the fstab entry.
#
# @param passno
#    Order the filesystem is checked by fsck, the sixth field of the fstab entry.
#
# @param target
#    File to manage. Only meant to be changed by tests.
#
# @example
#   cis_security_hardening::fstab_entry { '/boot/efi':
#     mountpoint   => '/boot/efi',
#     spec         => 'UUID=BC04-FDA2',
#     fstype       => 'vfat',
#     mountoptions => ['umask=0077', 'fmask=0077', 'uid=0', 'gid=0'],
#     passno       => 1,
#   }
define cis_security_hardening::fstab_entry (
  Cis_security_hardening::Mountpoint $mountpoint,
  Pattern[/\A\S+\z/]                 $spec,
  Pattern[/\A\S+\z/]                 $fstype,
  Array[Pattern[/\A\S+\z/], 1]       $mountoptions = ['defaults'],
  Integer[0, 1]                      $dump         = 0,
  Integer[0, 2]                      $passno       = 0,
  Stdlib::Absolutepath               $target       = '/etc/fstab',
) {
  # The fstab lens stores "umask=0077" as opt = 'umask' with a child value = '0077', never with the '='
  $opt_changes = $mountoptions.map |Integer $index, String $option| {
    $parts = split($option, '=')
    $num   = $index + 1

    if length($parts) > 1 {
      [
        "set 01/opt[${num}] ${parts[0]}",
        "set 01/opt[${num}]/value ${join($parts[1, -1], '=')}",
      ]
    } else {
      ["set 01/opt[${num}] ${option}"]
    }
  }

  # 01 is the Augeas idiom for "a new entry", the lens renumbers the sequence on save
  $changes = flatten([
    "rm *[file = '${mountpoint}']",
    "set 01/spec ${spec}",
    "set 01/file ${mountpoint}",
    "set 01/vfstype ${fstype}",
    $opt_changes,
    "set 01/dump ${dump}",
    "set 01/passno ${passno}",
  ])

  # Deliberately no onlyif: the removal has to be attempted on every run, otherwise
  # duplicates added outside of Puppet survive. Augeas writes the file only when the
  # serialised result differs, so the resource is still idempotent.
  augeas { "${target} - single entry for ${mountpoint}":
    lens    => 'Fstab.lns',
    incl    => $target,
    context => "/files${target}",
    changes => $changes,
  }
}
