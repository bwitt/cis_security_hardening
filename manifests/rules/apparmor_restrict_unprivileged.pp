# @summary
#    Ensure kernel.apparmor_restrict_unprivileged_unconfined is enabled
#
# The kernel.apparmor_restrict_unprivileged_unconfined kernel parameter controls whether
# unprivileged user namespaces created by unconfined processes are restricted by AppArmor.
# Setting it to 1 ensures such namespaces remain subject to AppArmor mediation.
#
# Rationale:
# Unprivileged user namespaces significantly expand the kernel attack surface available to
# an unprivileged local user. Restricting unconfined unprivileged user namespaces ensures
# AppArmor policy continues to apply, limiting the impact of a namespace-based local
# privilege escalation.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::apparmor_restrict_unprivileged':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apparmor_restrict_unprivileged (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl { 'kernel.apparmor_restrict_unprivileged_unconfined':
      ensure => present,
      value  => 1,
    }
  }
}
