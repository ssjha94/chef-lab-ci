# Chef InSpec tests for recipe base_cookbook::default.

marker_path = os.windows? ? 'C:/chef/base_cookbook_marker.txt' : '/tmp/base_cookbook_marker.txt'
client_rb_path = os.windows? ? 'C:/chef/client.rb' : '/etc/chef/client.rb'

control 'base-cookbook-1.0' do
  impact 0.7
  title 'Verify base_cookbook marker file'
  desc 'The base_cookbook recipe should create a marker file.'

  describe file(marker_path) do
    it { should exist }
    its('content') { should match(/base_cookbook applied successfully/) }
  end

  describe file(marker_path), if: !os.windows? do
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'base-cookbook-2.0' do
  impact 1.0
  title 'Verify data_collector configuration in client.rb'
  desc 'The client.rb should contain data_collector.server_url and data_collector.token.'

  describe file(client_rb_path) do
    it { should exist }
    its('content') { should match(/data_collector\.server_url/) }
    its('content') { should match(/data_collector\.token/) }
  end
end

control 'base-cookbook-3.0' do
  impact 0.5
  title 'Verify Chef client is installed'
  desc 'Chef Infra Client should be installed.'

  describe command('chef-client --version') do
    its('exit_status') { should eq 0 }
  end
end
