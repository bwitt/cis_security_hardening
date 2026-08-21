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
def read_dot_file_status(local_interactive_users)
  alert_only = []
  strict_perm_files = []
  moderate_perm_files = []
  wrong_owner = {}
  wrong_group = {}
  shared = []
  group_unresolvable = []

  canonical_home = {}
  local_interactive_users.each do |user, home|
    canonical_home[user] = if File.directory?(home)
                             begin
                               File.realpath(home)
                             rescue SystemCallError
                               home
                             end
                           else
                             home
                           end
  end
  home_counts = canonical_home.values.tally
  seen_homes = []

  local_interactive_users.each do |user, home|
    next unless File.directory?(home)

    is_shared = home_counts[canonical_home[user]] > 1
    if is_shared
      next if seen_homes.include?(home)

      seen_homes.push(home)
    end

    # nil when the user's primary group can't be resolved via NSS (e.g. an
    # /etc/passwd entry whose gid has no corresponding group, or an NSS/LDAP
    # hiccup) -- in that case we don't know what group *would* be correct, so
    # there's no safe chgrp target; alert instead of silently skipping the
    # group check entirely.
    primary_group = begin
      Etc.getgrgid(Etc.getpwnam(user).gid).name
    rescue ArgumentError
      nil
    end

    Dir.glob(File.join(home, '.*')).each do |path|
      next unless File.file?(path) && !File.symlink?(path)

      base = File.basename(path)

      if ['.forward', '.rhosts'].include?(base)
        alert_only.push(path)
        next
      end

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
