# @summary
#    Ensure Xwayland is configured
#
# GDM can run its session under Wayland with Xwayland providing compatibility for X11
# clients. This rule sets WaylandEnable=false in the [daemon] block of the GDM configuration.
# If GDM is not installed the recommendation is not applicable.
#
# Rationale:
# Xwayland increases the attack surface of the graphical session by keeping an X11 server
# available to any client that asks for one.
#
# @param enforce
#    Enforce the rule
#
# @param config_file
#    The GDM configuration file to edit
#
# @example
#   class { 'cis_security_hardening::rules::xwayland':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::xwayland (
  Boolean $enforce                            = false,
  Optional[Stdlib::Absolutepath] $config_file = undef,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')

  if $enforce and $gnome_gdm != undef and $gnome_gdm {
    $file = $config_file ? {
      undef   => $facts['os']['name'].downcase() ? {
        'rocky'     => '/etc/gdm/custom.conf',
        'almalinux' => '/etc/gdm/custom.conf',
        'redhat'    => '/etc/gdm/custom.conf',
        'centos'    => '/etc/gdm/custom.conf',
        default     => '/etc/gdm3/custom.conf',
      },
      default => $config_file,
    }

    file_line { 'gdm waylandenable':
      ensure             => present,
      path               => $file,
      line               => 'WaylandEnable=false',
      match              => '^\s*#?\s*WaylandEnable\s*=',
      append_on_no_match => true,
      after              => '^\[daemon\]',
    }
  }
}
