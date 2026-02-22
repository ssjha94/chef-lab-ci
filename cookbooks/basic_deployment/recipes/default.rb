#
# Cookbook:: basic_deployment
# Recipe:: default
#
# Copyright:: 2026, The Authors, All Rights Reserved.

# Include compliance profiles for Chef Infra Compliance Phase
include_profile 'basic_deployment::basic_deployment_compliance'

file '/tmp/deployment_marker.txt' do
  content 'this is new server deployment'
  owner 'root'
  group 'root'
  mode '0644'
  action :create
end
