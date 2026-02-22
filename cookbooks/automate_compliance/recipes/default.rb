#
# Cookbook:: automate_compliance
# Recipe:: default
#
# Copyright:: 2026, The Authors, All Rights Reserved.
#
# This cookbook enables Chef Automate-managed compliance scanning
# Profiles are fetched from Chef Automate and run during the compliance phase
# Results are reported back to Chef Automate

# The Compliance Phase is built into Chef Infra Client (v15+)
# It runs automatically based on attributes in this cookbook
# No need to include audit cookbook - just set attributes
