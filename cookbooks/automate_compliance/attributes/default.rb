# Enable compliance phase to fetch and run profiles from Chef Automate
default['audit']['compliance_phase'] = true

# Set profile location - fetch from Chef Automate
default['audit']['profiles']['cis-ubuntu22.04lts-level1-server'] = {
  'compliance' => 'admin/cis-ubuntu22.04lts-level1-server',
}

# Fetch additional profiles from Chef Automate
default['audit']['fetcher'] = 'chef-automate'

# Set reporter to send results to Chef Automate
default['audit']['reporter'] = 'chef-automate'
