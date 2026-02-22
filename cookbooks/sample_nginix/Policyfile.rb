name 'sample_nginix'
default_source :supermarket

# Use the default recipe explicitly to avoid policy/run_list mismatches
run_list 'sample_nginix::default'

cookbook 'sample_nginix', path: '.'
