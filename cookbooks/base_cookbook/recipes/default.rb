#
# Cookbook:: base_cookbook
# Recipe:: default
#
# Copyright:: 2026, The Authors, All Rights Reserved.

# Guard for older chef-client versions that do not expose compliance helpers.
if respond_to?(:include_profile)
  include_profile 'base_cookbook::base_cookbook_compliance'
else
  log 'Chef Infra Client does not expose include_profile helper; skipping compliance profile include.'
end

if platform_family?('windows')
  include_recipe 'base_cookbook::windows'
else
  include_recipe 'base_cookbook::linux'
end
