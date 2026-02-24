#
# Cookbook:: base_cookbook
# Resource:: data_collector_config
#
# Copyright:: 2026, The Authors, All Rights Reserved.

unified_mode true

property :client_rb_path, String, name_property: true
property :data_collector_url, String, required: true
property :data_collector_token, String, required: true
property :file_mode, [String, nil], default: nil

action :configure do
  directory ::File.dirname(new_resource.client_rb_path) do
    recursive true
  end

  file new_resource.client_rb_path do
    content lazy { ::File.exist?(new_resource.client_rb_path) ? ::File.read(new_resource.client_rb_path) : '' }
    action :create_if_missing
    mode new_resource.file_mode if new_resource.file_mode
  end

  if new_resource.data_collector_url.empty? || new_resource.data_collector_token.empty?
    log "base_cookbook data_collector url/token is empty for #{new_resource.client_rb_path}; skipping client.rb data_collector configuration."
  else
    ruby_block "configure_data_collector_#{new_resource.name}" do
      block do
        current = ::File.exist?(new_resource.client_rb_path) ? ::File.read(new_resource.client_rb_path) : ''
        filtered_lines = current.lines.reject do |line|
          line.match?(/^\s*#\s*Managed by Chef base_cookbook\b/) ||
            line.match?(/^\s*data_collector\.server_url\b/) ||
            line.match?(/^\s*data_collector\.token\b/)
        end

        managed_lines = [
          '# Managed by Chef base_cookbook',
          %(data_collector.server_url "#{new_resource.data_collector_url}"),
          %(data_collector.token "#{new_resource.data_collector_token}"),
        ]

        desired = filtered_lines.join
        desired = desired.sub(/\s*\z/, '')
        desired += "\n\n" unless desired.empty?
        desired += managed_lines.join("\n")
        desired += "\n"

        next if desired == current

        ::File.write(new_resource.client_rb_path, desired)
      end
      action :run
    end

    file new_resource.client_rb_path do
      mode new_resource.file_mode
      only_if { !new_resource.file_mode.nil? }
    end
  end
end
