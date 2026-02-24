# base_cookbook

Configures data_collector reporting to Chef Automate and sets audit compliance phase attributes.

## What this cookbook does

1. **Recipe (`recipes/default.rb`)**:
   - Manages `client.rb` data collector settings on Linux and Windows.
   - Linux path: `/etc/chef/client.rb`
   - Windows path: `C:/chef/client.rb`
   - Creates a marker file:
   - Linux: `/tmp/base_cookbook_marker.txt`
   - Windows: `C:/chef/base_cookbook_marker.txt`

2. **Attributes (`attributes/default.rb`)**: Sets `audit['compliance_phase']`, `audit['reporter']`, and `audit['fetcher']` so InSpec profiles run during the compliance phase and report to Automate.

3. **Compliance Profile (`compliance/profiles/base_cookbook_compliance/`)**: InSpec controls that verify:
   - Marker file exists with correct content
   - `client.rb` contains data_collector configuration
   - Chef client is installed

## Usage

Add `base_cookbook::default` to your run_list or include it in your Policyfile:

```ruby
run_list 'base_cookbook::default'
```

Set data collector values with Policyfile attributes (recommended) so secrets are not hardcoded in the cookbook:

```ruby
default['base_cookbook']['data_collector']['url'] = 'https://YOUR-AUTOMATE/data-collector/v0/'
default['base_cookbook']['data_collector']['token'] = 'YOUR_DATA_COLLECTOR_TOKEN'
```

## Attributes

| Attribute | Default | Description |
|-----------|---------|-------------|
| `node['audit']['compliance_phase']` | `true` | Enable Chef Infra Compliance Phase |
| `node['audit']['reporter']` | `'chef-automate'` | Report compliance results to Automate |
| `node['audit']['fetcher']` | `'chef-automate'` | Fetch compliance profiles from Automate |
| `node['base_cookbook']['data_collector']['url']` | `''` | Data collector endpoint |
| `node['base_cookbook']['data_collector']['token']` | `''` | Data collector authentication token |
