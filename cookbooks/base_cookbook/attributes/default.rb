# Audit / Compliance Phase attributes
default['audit']['compliance_phase'] = true
default['audit']['reporter'] = 'chef-automate'
default['audit']['fetcher'] = 'chef-automate'
default['audit']['quiet'] = false

# Data Collector settings
# Keep token out of source control. Set these in Policyfile/node attributes or
# with a secure secret mechanism before converge.
default['base_cookbook']['data_collector']['url'] = ''
default['base_cookbook']['data_collector']['token'] = ''
