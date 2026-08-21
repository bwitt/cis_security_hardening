# frozen_string_literal: true

require 'etc'

# for each local interactive user, report home directory existence, ownership
# mismatch, and excess-permission status (group-write or other rwx bits set,
# i.e. anything beyond mode 0750)
#
# home directories can be shared by more than one interactive user (a real,
# if unusual, misconfiguration). excess_perms is deduped by path since the
# permission check doesn't depend on which user is "correct" -- but ownership
# is genuinely ambiguous when shared, so a shared home is reported via
# home_dir_shared (alert-only) instead of guessing an owner and auto-chowning.
def read_home_dir_status(local_interactive_users)
  missing = []
  wrong_owner = {}
  excess_perms = []
  shared = []

  home_counts = local_interactive_users.values.tally

  local_interactive_users.each do |user, home|
    unless File.directory?(home)
      missing.push(user)
      next
    end

    if home_counts[home] > 1
      shared.push(home) unless shared.include?(home)
      excess_perms.push(home) if (File.stat(home).mode & 0o027) != 0 && !excess_perms.include?(home)
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
    'home_dir_excess_perms' => excess_perms.uniq,
    'home_dir_shared'       => shared,
  }
end
