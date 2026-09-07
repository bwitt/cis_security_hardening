# @summary
#    Manage permissions below a directory
#
# Enforce modes and ownership on everything below a directory without declaring
# a file resource per entry.
#
# @param target_dir
#    Directory to work on
#
# @param file_mode
#    Mode to enforce on files
#
# @param dir_mode
#    Mode to enforce on directories
#
# @param owner
#    Owner to enforce
#
# @param group
#    Group to enforce
#
# @example
#   cis_security_hardening::recursive_file_permissions { '/var/log':
#     file_mode => '0640',
#     dir_mode  => '0755',
#   }
#
define cis_security_hardening::recursive_file_permissions (
  Stdlib::Absolutepath $target_dir      = $title,
  Optional[Stdlib::Filemode] $file_mode = undef,
  Optional[Stdlib::Filemode] $dir_mode  = undef,
  Optional[String[1]] $owner            = undef,
  Optional[String[1]] $group            = undef,
) {
  if !$file_mode and !$dir_mode and !$owner and !$group {
    fail('one of file_mode, dir_mode, owner or group is required')
  }

  $dir = stdlib::shell_escape($target_dir)

  $actions = [
    { 'set' => $file_mode, 'test' => "-type f ! -perm ${file_mode}", 'fix' => "chmod -c ${file_mode}" },
    { 'set' => $dir_mode,  'test' => "-type d ! -perm ${dir_mode}",  'fix' => "chmod -c ${dir_mode}" },
    { 'set' => $owner,     'test' => "! -user ${owner}",             'fix' => "chown -ch ${owner}" },
    { 'set' => $group,     'test' => "! -group ${group}",            'fix' => "chgrp -ch ${group}" },
  ].filter |$action| { $action['set'] =~ NotUndef }

  $tests = $actions.map |$action| { "\\( ${action['test']} \\)" }
  $fixes = $actions.map |$action| { "find ${dir} ${action['test']} -exec ${action['fix']} {} +" }

  exec { "recursive_file_permissions ${target_dir}":
    command   => join($fixes, ' && '),
    onlyif    => "test -d ${dir} && test -n \"\$(find ${dir} \\( ${join($tests, ' -o ')} \\) -print -quit)\"",
    provider  => shell,
    path      => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    logoutput => true,
  }
}
