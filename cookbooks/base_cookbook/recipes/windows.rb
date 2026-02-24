#
# Cookbook:: base_cookbook
# Recipe:: windows
#
# Copyright:: 2026, The Authors, All Rights Reserved.

client_rb_path = 'C:/chef/client.rb'
marker_path = 'C:/chef/base_cookbook_marker.txt'
data_collector_url = node['base_cookbook']['data_collector']['url'].to_s.strip
data_collector_token = node['base_cookbook']['data_collector']['token'].to_s.strip

base_cookbook_data_collector_config client_rb_path do
  data_collector_url data_collector_url
  data_collector_token data_collector_token
  action :configure
end

file marker_path do
  content 'base_cookbook applied successfully'
  action :create
end
