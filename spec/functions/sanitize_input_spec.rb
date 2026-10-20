# frozen_string_literal: true

require 'spec_helper'

describe 'sanitize_input' do
  it { is_expected.to run.with_params('allow').and_return('allow') }
  it { is_expected.to run.with_params('allow; rm -rf /').and_return('allow\;\ rm\ -rf\ /') }
  it { is_expected.to run.with_params('').and_return("''") }
  it { is_expected.to run.with_params(nil).and_raise_error(StandardError) }
end
