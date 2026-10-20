# frozen_string_literal: true

# check if a package is installed
# params:
#    opts: rpm options to use
#    pkg:  package name to query
def check_package_installed(pkg, opts = '-q')
  os = Facter.value(:osfamily)
  if (os == 'RedHat') || (os == 'Suse')
    val = Facter::Core::Execution.exec("rpm #{opts} #{pkg}")
  elsif os == 'Debian'
    opts = '' if opts == '-q'
    opts = "#{opts} -l"
    val = Facter::Core::Execution.exec("dpkg #{opts} #{pkg} | grep ^ii")
  end

  !val.nil? && !val.empty? && !val.include?('not installed')
end
