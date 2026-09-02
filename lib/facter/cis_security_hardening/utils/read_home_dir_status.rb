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
#
# sharing is detected on the canonicalized (realpath) form of each home, not
# the raw /etc/passwd string, so two entries pointing at the same real
# directory via differently-formatted paths (trailing slash, a symlink, etc.)
# are still recognized as shared rather than each being treated as unshared.
# A shared home is reported/acted on via its canonical path exactly once,
# not once per raw alias -- otherwise two users sharing a home via
# differently-formatted paths would each get their own notify/exec resource
# for what is really the same directory.
#
# Takes the already-computed read_canonical_homes result (not
# local_interactive_users directly) so callers that also call
# read_dot_file_status on the same users only pay the File.stat/realpath
# syscalls once, not once per fact.
def read_home_dir_status(canonical_homes)
  missing = []
  wrong_owner = {}
  excess_perms = []
  shared = []
  seen_canonical_homes = []

  home_counts = canonical_homes.values.map { |info| info['canonical'] }.tally

  canonical_homes.each do |user, info|
    unless info['exists']
      missing.push(user)
      next
    end

    home = info['home']
    canonical = info['canonical']

    if home_counts[canonical] > 1
      next if seen_canonical_homes.include?(canonical)

      stat = begin
        File.stat(home)
      rescue SystemCallError
        next
      end

      seen_canonical_homes.push(canonical)

      shared.push(canonical)
      excess_perms.push(canonical) if (stat.mode & 0o027) != 0
      next
    end

    stat = begin
      File.stat(home)
    rescue SystemCallError
      # home vanished between the directory? check in read_canonical_homes
      # and here (e.g. deleted, unmounted, or an automounter tearing it down
      # mid-scan) -- nothing left to evaluate
      next
    end

    expected_uid = begin
      Etc.getpwnam(user).uid
    rescue ArgumentError
      nil
    end
    wrong_owner[home] = user if expected_uid.nil? || stat.uid != expected_uid
    excess_perms.push(home) if (stat.mode & 0o027) != 0
  end

  {
    'missing_home_dir'      => missing,
    'home_dir_wrong_owner'  => wrong_owner,
    'home_dir_excess_perms' => excess_perms.uniq,
    'home_dir_shared'       => shared,
  }
end
