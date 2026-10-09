# @summary
#    Add a keyfile and locks to a dconf database
#
# dconf::db owns its database directory, so use this where several rules
# contribute settings to the same database.
#
# @param db
#    Name of the dconf database, eg local or gdm
#
# @param settings
#    Settings to write
#
# @param locks
#    Keys to lock
#
# @example
#   cis_security_hardening::dconf_db_entry { '01-lock-enabled':
#     db       => 'local',
#     settings => { 'org/gnome/desktop/screensaver' => { 'lock-enabled' => 'true' } },
#     locks    => ['/org/gnome/desktop/screensaver/lock-enabled'],
#   }
#
define cis_security_hardening::dconf_db_entry (
  String[1] $db,
  Optional[Hash] $settings = undef,
  Optional[Array] $locks   = undef,
) {
  include dconf

  $db_dir    = "${dconf::db_base_dir}/${db}.d"
  $locks_dir = "${db_dir}/locks"

  ensure_resource('file', $db_dir, {
    ensure  => 'directory',
    mode    => '0755',
    purge   => true,
    recurse => true,
    force   => true,
  })

  ensure_resource('file', $locks_dir, {
    ensure  => 'directory',
    mode    => '0755',
    purge   => true,
    recurse => true,
  })

  if $settings {
    dconf::db_keyfile { $name:
      parent_db => $db_dir,
      filename  => $name,
      settings  => $settings,
    }
  }

  if $locks {
    dconf::db_locks { $name:
      parent_db => $db_dir,
      filename  => $name,
      locks     => $locks,
    }
  }
}
