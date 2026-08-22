# frozen_string_literal: true

require 'etc'

# for each local interactive user, categorize top-level dotfiles (no recursion
# into subdirectories) in their home directory for the dot-files access
# control: .forward/.rhosts are alert-only (CIS's own remediation is "list for
# manual deletion", not an automatic action); .netrc/.bash_history need strict
# permissions (0600 or more restrictive); every other dotfile needs moderate
# permissions (0644 or more restrictive); all dotfiles are ownership-checked
#
# a home directory can be shared by more than one interactive user. dotfiles
# under a shared home are permission-checked normally (deduped by path, since
# the permission check doesn't depend on which user is "correct"), but
# ownership/group are genuinely ambiguous when shared -- rather than guessing
# and auto-chowning to an arbitrary one of the sharing users, those paths are
# reported via dotfiles_shared (alert-only) instead.
#
# sharing is detected on the canonicalized (realpath) form of each home, not
# the raw /etc/passwd string, so two entries pointing at the same real
# directory via differently-formatted paths are still recognized as shared.
#
# Takes the already-computed read_canonical_homes result (not
# local_interactive_users directly) so callers that also call
# read_home_dir_status on the same users only pay the File.stat/realpath
# syscalls once, not once per fact.
def read_dot_file_status(canonical_homes)
  alert_only = []
  strict_perm_files = []
  moderate_perm_files = []
  wrong_owner = {}
  wrong_group = {}
  shared = []
  group_unresolvable = []

  home_counts = canonical_homes.values.map { |info| info['canonical'] }.tally
  seen_canonical_homes = []

  canonical_homes.each do |user, info|
    next unless info['exists']

    canonical = info['canonical']
    is_shared = home_counts[canonical] > 1
    if is_shared
      # dedup on the canonical path, not the raw /etc/passwd string -- two
      # users sharing a home via differently-formatted paths (trailing
      # slash, a symlink) must still only be globbed/evaluated once
      next if seen_canonical_homes.include?(canonical)

      seen_canonical_homes.push(canonical)
    end

    # nil when the user's primary group can't be resolved via NSS (e.g. an
    # /etc/passwd entry whose gid has no corresponding group, or an NSS/LDAP
    # hiccup) -- in that case we don't know what group *would* be correct, so
    # there's no safe chgrp target; alert instead of silently skipping the
    # group check entirely. Only needed for non-shared homes, since shared
    # homes never reach the ownership/group check below.
    primary_group = unless is_shared
                      begin
                        Etc.getgrgid(Etc.getpwnam(user).gid).name
                      rescue ArgumentError
                        nil
                      end
                    end

    Dir.glob(File.join(canonical, '.*')).each do |path|
      base = File.basename(path)

      # checked before the file?/symlink? guard below: CIS's concern with
      # .forward/.rhosts is their mere presence (mail redirection, rcp/rlogin
      # trust bypass), so a symlinked .forward is exactly as much a finding
      # as a regular one -- excluding symlinks here would let a user evade
      # the alert simply by symlinking it instead of creating it directly.
      if ['.forward', '.rhosts'].include?(base)
        alert_only.push(path)
        next
      end

      next unless File.file?(path) && !File.symlink?(path)

      stat = begin
        File.stat(path)
      rescue SystemCallError
        # file vanished between the check above and here (e.g. deleted or
        # rotated mid-scan) -- nothing left to evaluate
        next
      end

      if is_shared
        shared.push(path)
      else
        owner = begin
          Etc.getpwuid(stat.uid).name
        rescue ArgumentError
          nil
        end
        group = begin
          Etc.getgrgid(stat.gid).name
        rescue ArgumentError
          nil
        end
        wrong_owner[path] = user if owner != user
        if primary_group
          wrong_group[path] = primary_group if group != primary_group
        else
          group_unresolvable.push(path)
        end
      end

      if ['.netrc', '.bash_history'].include?(base)
        strict_perm_files.push(path) if (stat.mode & 0o177) != 0
      elsif (stat.mode & 0o133) != 0
        moderate_perm_files.push(path)
      end
    end
  end

  {
    'dotfiles_alert_only' => alert_only.uniq,
    'dotfiles_strict_perm' => strict_perm_files.uniq,
    'dotfiles_moderate_perm' => moderate_perm_files.uniq,
    'dotfiles_wrong_owner' => wrong_owner,
    'dotfiles_wrong_group' => wrong_group,
    'dotfiles_shared' => shared.uniq,
    'dotfiles_group_unresolvable' => group_unresolvable.uniq,
  }
end
