# @summary
#    Ensure automatic mounting and autorun of removable media is disabled
#
# By default GNOME automatically mounts removable media when inserted, and autoruns content on it,
# as a convenience to the user.
#
# Rationale:
# With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents
# available in system even if they lacked permissions to mount it themselves. Autorun compounds this by letting
# malware on that media execute automatically.
#
# Impact:
# The use of portable hard drives is very common for workstation users. If your organization allows the use of
# portable storage or media on workstations and physical access controls to workstations is considered adequate
# there is little value add in turning off automounting.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::gdm_auto_mount':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_auto_mount (
  Boolean $enforce = false,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    include dconf
    # automount/automount-open and autorun-never are independent CIS controls (1.7.6/1.7.7 vs
    # 1.7.8/1.7.9) and both apply regardless of OS -- previously these were mutually exclusive
    # (an if/else keyed on `os.name == 'debian'`), which meant Ubuntu (os.name == 'Ubuntu', not
    # an exact match) only ever got automount/automount-open and never autorun-never, while actual
    # Debian only ever got autorun-never and never automount/automount-open. One combined
    # dconf::db resource, gated only on gnome_gdm being present, covers all four settings on any
    # OS that has GDM at all.
    dconf::db { 'media-automount':
      db_dir         => "${dconf::db_base_dir}/local.d",
      db_filename    => '00-media-automount',
      locks_filename => '00-media-automount',
      settings       => {
        'org/gnome/desktop/media-handling' => {
          'automount'      => 'false',
          'automount-open' => 'false',
          'autorun-never'  => 'true',
        },
      },
      locks          => [
        '/org/gnome/desktop/media-handling/automount',
        '/org/gnome/desktop/media-handling/automount-open',
        '/org/gnome/desktop/media-handling/autorun-never',
      ],
    }
  }
}
