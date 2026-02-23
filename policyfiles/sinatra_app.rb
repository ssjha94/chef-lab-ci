# Policyfile.rb - Describe how you want Chef Infra Client to build your system.
#
# For more information on the Policyfile feature, visit
# https://docs.chef.io/policyfile/

# A name that describes what the system you're building with Chef does.
name 'sinatra_app'

# This lets you source cookbooks from your chef-repo.
default_source :chef_repo, '../'

# Where to find external cookbooks:
# default_source :supermarket

# run_list: chef-client will run these recipes in the order specified.
run_list 'deploy_sinatra_app::default'

# Specify a custom source for a single cookbook:
cookbook 'sinatra_app', path: '../cookbooks/deploy_sinatra_app'
