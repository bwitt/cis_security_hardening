# frozen_string_literal: true

require 'etc'

# for each local interactive user, report home directory existence, ownership
# mismatch, and excess-permission status (group-write or other rwx bits set,
# i.e. anything beyond mode 0750)
def read_home_dir_status(local_interactive_users)
  missing = []
  wrong_owner = {}
  excess_perms = []

  local_interactive_users.each do |user, home|
    unless File.directory?(home)
      missing.push(user)
      next
    end

    stat = File.stat(home)
    owner = begin
      Etc.getpwuid(stat.uid).name
    rescue ArgumentError
      nil
    end
    wrong_owner[home] = user if owner != user
    excess_perms.push(home) if (stat.mode & 0o027) != 0
  end

  {
    'missing_home_dir'      => missing,
    'home_dir_wrong_owner'  => wrong_owner,
    'home_dir_excess_perms' => excess_perms,
  }
end
