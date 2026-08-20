# frozen_string_literal: true

require 'spec_helper'
require 'facter/cis_security_hardening/utils/read_duplicate_ids'

describe 'read_duplicate_ids' do
  before do
    allow(File).to receive(:readlines).with('/etc/passwd').and_return(
      [
        "root:x:0:0:root:/root:/bin/bash\n",
        "userone:x:1000:1000::/home/userone:/bin/bash\n",
        "usertwo:x:1000:1000::/home/usertwo:/bin/bash\n",
        "userthree:x:1001:1001::/home/userthree:/bin/bash\n",
      ]
    )
  end

  it 'returns ids used by more than one name' do
    expect(read_duplicate_ids('/etc/passwd', 2, 0)).to eq('1000' => %w[userone usertwo])
  end

  it 'excludes ids used by only one name' do
    result = read_duplicate_ids('/etc/passwd', 2, 0)
    expect(result).not_to have_key('0')
    expect(result).not_to have_key('1001')
  end
end
