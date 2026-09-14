# frozen_string_literal: true

require 'date'

# an unset aging field reads as -1, which is what chage reports for it, not 0
def shadow_number(value)
  value.empty? ? -1 : value.to_i
end

# read local users
def read_local_users
  local_users = {}
  today = (Date.today - Date.new(1970, 1, 1)).to_i

  begin
    lines = File.readlines('/etc/shadow')
  rescue SystemCallError, IOError
    return local_users
  end

  lines.each do |line|
    fields = line.chomp.split(':', -1)
    next if fields.length < 8

    user, password, lastchg, min, max, warn, inactive, expire = fields

    next if password.start_with?('!', '*')

    max_days = max.empty? ? nil : max.to_i

    must_change   = !lastchg.empty? && lastchg.to_i.zero?
    aging_unset   = lastchg.empty?
    never_expires = max_days.nil? || max_days >= 10_000

    if must_change
      last_password_change_days = 'password must be changed'
      password_expires_days     = 'password must be changed'
      password_inactive_days    = 'password must be changed'
      password_date_valid       = nil
    elsif aging_unset
      last_password_change_days = 'never'
      password_expires_days     = 'never'
      password_inactive_days    = 'never'
      password_date_valid       = nil
    else
      lastchg_days = lastchg.to_i

      last_password_change_days = today - lastchg_days
      password_date_valid       = lastchg_days <= today

      password_expires_days = never_expires ? 'never' : (lastchg_days + max_days) - today

      password_inactive_days = if inactive.empty? || never_expires
                                 'never'
                               else
                                 inactive.to_i
                               end
    end

    account_expires_days = expire.empty? ? 'never' : expire.to_i - today

    local_users[user] = {
      'last_password_change_days'         => last_password_change_days,
      'password_expires_days'             => password_expires_days,
      'password_inactive_days'            => password_inactive_days,
      'account_expires_days'              => account_expires_days,
      'min_days_between_password_change'  => shadow_number(min),
      'max_days_between_password_change'  => shadow_number(max),
      'warn_days_between_password_change' => shadow_number(warn),
      'password_date_valid'               => password_date_valid,
    }
  end

  local_users
end
