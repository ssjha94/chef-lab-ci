# my_policy.rb

# Define the name and default version of the policy
name 'testenv1'

# Specify the cookbooks and their versions
cookbook 'rhel_config', '~> 0.1.0'
cookbook 'iis_server', '~> 0.1.0'

# Define the run-list for your nodes
run_list 'recipe[rhel_config::default]', 'recipe[iis_server::default]'

# Define attributes for the policy
default['my_policy']['package_manager'] = if platform_family?('debian')
                                            'apt'
                                          elsif platform_family?('rhel')
                                            'yum'
                                          else
                                            'unknown'
                                          end

# Define environment-specific attributes
default['my_policy']['development']['debug'] = true
default['my_policy']['production']['debug'] = false

# Specify the environment to use
environment 'development' do
  default['my_policy']['debug'] = true
end

environment 'production' do
  default['my_policy']['debug'] = false
end
