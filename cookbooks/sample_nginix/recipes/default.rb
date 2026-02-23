#
# Cookbook:: sample_nginix
# Recipe:: default
#
# Copyright:: 2026, The Authors, All Rights Reserved.

# Include compliance profiles for Chef Infra Compliance Phase
include_profile 'sample_nginix::nginx_compliance'
include_profile 'sample_nginix::cis-ubuntu22'

# Update package cache
apt_update 'update' do
  action :update
  only_if { platform_family?('debian') }
end

# Install nginx
package 'nginx' do
  action :install
end

# Enable and start nginx service
service 'nginx' do
  action [:enable, :start]
  supports status: true, restart: true, reload: true
end

# Create a custom index.html
template '/var/www/html/index.html' do
  source 'index.html.erb'
  owner 'root'
  group 'root'
  mode '0644'
  notifies :reload, 'service[nginx]', :delayed
  only_if { platform_family?('debian') }
end

# For RHEL/CentOS, the default path is different
template '/usr/share/nginx/html/index.html' do
  source 'index.html.erb'
  owner 'root'
  group 'root'
  mode '0644'
  notifies :reload, 'service[nginx]', :delayed
  only_if { platform_family?('rhel') }
end
