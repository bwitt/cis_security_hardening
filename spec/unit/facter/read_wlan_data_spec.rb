# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/facter/cis_security_hardening/utils/read_wlan_data'

describe 'read_wlan_data' do
  before do
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:directory?).and_call_original
    allow(File).to receive(:realpath).and_call_original
    allow(File).to receive(:exist?).with('/usr/bin/nmcli').and_return(false)
  end

  # names: every interface present; wireless: which of them are wireless;
  # modules: interface name => driver module behind it
  def with_interfaces(names, wireless: [], modules: {})
    allow(Dir).to receive(:glob).with('/sys/class/net/*').and_return(names.map { |n| "/sys/class/net/#{n}" })
    names.each do |n|
      allow(File).to receive(:directory?).with("/sys/class/net/#{n}/wireless").and_return(false)
      allow(File).to receive(:exist?).with("/sys/class/net/#{n}/phy80211").and_return(wireless.include?(n))

      link = "/sys/class/net/#{n}/device/driver/module"
      allow(File).to receive(:exist?).with(link).and_return(modules.key?(n))
      allow(File).to receive(:realpath).with(link).and_return("/sys/module/#{modules[n]}") if modules.key?(n)
    end
  end

  context 'when detecting interfaces' do
    it 'finds interfaces under systemd predictable names' do
      with_interfaces(%w[lo eth0 wlp3s0], wireless: %w[wlp3s0])
      result = read_wlan_data
      expect(result['wlan_interfaces']).to eq(['wlp3s0'])
      expect(result['wlan_interfaces_count']).to eq(1)
    end

    it 'still finds the legacy wlan naming' do
      with_interfaces(%w[lo eth0 wlan0], wireless: %w[wlan0])
      expect(read_wlan_data['wlan_interfaces']).to eq(['wlan0'])
    end

    it 'reports none when no interface is wireless' do
      with_interfaces(%w[lo eth0])
      result = read_wlan_data
      expect(result['wlan_interfaces']).to eq([])
      expect(result['wlan_interfaces_count']).to eq(0)
    end

    it 'does not report an ethernet interface whose name happens to contain wlan' do
      with_interfaces(%w[lo br-wlan0])
      expect(read_wlan_data['wlan_interfaces_count']).to eq(0)
    end

    it 'detects the wext style wireless directory' do
      allow(Dir).to receive(:glob).with('/sys/class/net/*').and_return(['/sys/class/net/wlan0'])
      allow(File).to receive(:directory?).with('/sys/class/net/wlan0/wireless').and_return(true)
      allow(File).to receive(:exist?).with('/sys/class/net/wlan0/device/driver/module').and_return(false)
      expect(read_wlan_data['wlan_interfaces']).to eq(['wlan0'])
    end
  end

  context 'when resolving driver modules' do
    it 'reports the module behind a wireless interface' do
      with_interfaces(%w[lo eth0 wlp3s0], wireless: %w[wlp3s0], modules: { 'wlp3s0' => 'iwlwifi' })
      expect(read_wlan_data['wlan_modules']).to eq(['iwlwifi'])
    end

    it 'reports a shared module only once' do
      with_interfaces(%w[wlp3s0 wlp4s0], wireless: %w[wlp3s0 wlp4s0],
                                         modules: { 'wlp3s0' => 'ath9k', 'wlp4s0' => 'ath9k' })
      expect(read_wlan_data['wlan_modules']).to eq(['ath9k'])
    end

    it 'ignores the module behind a non-wireless interface' do
      with_interfaces(%w[eth0], modules: { 'eth0' => 'e1000e' })
      expect(read_wlan_data['wlan_modules']).to eq([])
    end

    it 'skips a wireless interface with no driver link' do
      with_interfaces(%w[wlan0], wireless: %w[wlan0])
      expect(read_wlan_data['wlan_modules']).to eq([])
    end
  end

  context 'with nmcli present' do
    before do
      allow(File).to receive(:exist?).with('/usr/bin/nmcli').and_return(true)
    end

    def with_radio(output)
      allow(Facter::Core::Execution).to receive(:exec).and_return(output)
    end

    it 'reports radio status but still resolves the modules' do
      with_radio('enabled')
      with_interfaces(%w[wlp3s0], wireless: %w[wlp3s0], modules: { 'wlp3s0' => 'iwlwifi' })
      result = read_wlan_data
      expect(result['wlan_status']).to eq('enabled')
      expect(result).not_to have_key('wlan_interfaces')
      expect(result['wlan_modules']).to eq(['iwlwifi'])
    end

    it 'reports a disabled radio' do
      with_radio('disabled')
      with_interfaces([])
      expect(read_wlan_data['wlan_status']).to eq('disabled')
    end

    # a host with no WWAN modem made the old table parse report an empty
    # status, so the rule never turned the radio off
    it 'is unaffected by hardware with no WWAN modem' do
      with_radio('enabled')
      with_interfaces([])
      expect(read_wlan_data['wlan_status']).to eq('enabled')
    end

    it 'falls back to disabled when NetworkManager is not running' do
      with_radio('Error: NetworkManager is not running.')
      with_interfaces([])
      expect(read_wlan_data['wlan_status']).to eq('disabled')
    end

    it 'falls back to disabled on unexpected output' do
      with_radio('')
      with_interfaces([])
      expect(read_wlan_data['wlan_status']).to eq('disabled')
    end
  end
end
