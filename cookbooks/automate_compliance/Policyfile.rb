name 'automate_compliance'
default_source :supermarket
run_list 'automate_compliance::default'
cookbook 'automate_compliance', path: '.'
