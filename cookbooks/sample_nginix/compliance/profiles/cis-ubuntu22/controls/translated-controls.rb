ipv6_status = input('ipv6_status', {
  title: 'Provide a value to specify the status of IPV6 in the system.',
  value: 'enabled',
  description: 'Provide a value to specify the status of IPV6 in the system in accordance with system requirements and local site policy. Provide the value as "enabled" or "disabled".',
})

firewall_utility = input('firewall_utility', {
  title: 'Firewall utility',
  value: 'ufw',
  description: 'In order to configure firewall rules a firewall utility needs to be installed ufw, nftables or iptables. Only one method should be used to configure a firewall on the system. Use of more than one method could produce unexpected results.',
})

iptables_established_connections = input('iptables_established_connections', {
  title: 'Expected appropriate value for iptables established connections.',
  value: [%w(INPUT OUTPUT), %w(tcp udp icmp)],
  description: 'Expected appropriate value for iptables established connections. Datatype for this should be Array of length 2 (on 0th index all rulesets and on 1st index all the connections should be mentioned as array of string).',
})

ip6tables_established_connections = input('ip6tables_established_connections', {
  title: 'Expected appropriate value for ip6tables established connections.',
  value: [%w(INPUT OUTPUT), %w(tcp udp icmp)],
  description: 'Expected appropriate value for ip6tables established connections. Datatype for this should be Array of length 2 (on 0th index all rulesets and on 1st index all the connections should be mentioned as array of string).',
})

su_group_name = input('su_group_name', {
  title: 'Provide a valid group name to be specified for use of the su command as per site policy',
  value: 'NOT_SET',
  description: 'Provide a valid group name to be specified for use of the su command as per site policy. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement with the group name specified in /etc/pam.d/su, the su command will only allow users in a specific groups to execute su. This group should be empty to reinforce the use of sudo for privileged access. Restricting the use of su , and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands.',
})

authentication_method = input('authentication_method', {
  title: 'Provide a valid authentication method.',
  value: 'password',
  description: 'If passwords are not being used for authentication, this is not applicable.',
})

match_directives_parameters = input('match_directives_parameters', {
  title: 'Connection parameter to configure the match directives.',
  value: 'NOT_SET',
  description: 'Specify the connection parameters to configuring Match directives.The connection parameters should be supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. Eg "-C user=root -C host='' -C addr='' -C laddr='' -C lport='' -C rdomain=''" or It should be like "NOT_SET".',
})

lport = input('lport', {
  title: 'Specify a value for lport.',
  value: 'NOT_SET',
  description: 'Please provide a value for lport that is not specified in any of the Match statements with LocalPort in the SSHD configuration files. The value should be a number that does not match any LocalPort defined in those Match sets. Eg 22. or If no LocalPort is used in any Match statements, please specify "NOT_SET".',
})

required_banner_message = input('required_banner_message', {
  title: 'Provide a valid banner message.',
  value: 'NOT_SET',
  description: 'Provide a valid  banner message as per site policy. By Default system has a Banner message as "Authorized users only. All activity may be monitored and reported.". The value should be regex string. If this parameter has a value "NOT_SET" and Default Banner message will get consider. Eg. "Authorized users only. All activity may be monitored and reported."',
})

log_capturing_method = input('log_capturing_method', {
  title: 'Preferred method for capturing logs.',
  value: 'journald',
  description: 'The preferred method for capturing logs.',
})

max_log_file = input('max_log_file', {
  title: 'Expected appropriate size value for max_log_file argument for log files',
  value: 8,
  description: 'Expected appropriate size value for max_log_file argument for log files',
})

sysctl_configuration_files = bash('find /run/sysctl.d/ /etc/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/ /etc/sysctl.conf -type f -regex .\\*/.\\*\\\\.conf').stdout.split
ipv6_status_system = bash('#!/usr/bin/env bash
check_ipv6()
{
  output=""
  grubfile=$(find /boot -type f \( -name "grubenv" -o -name "grub.conf" -o -name "grub.cfg" \) -exec grep -Pl -- "^\\h*(kernelopts=|linux|kernel)" {} \;)
  searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"
  if [ -s "$grubfile" ]; then
      ! grep -P -- "^\\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && output="IPv6 Disabled in \"$grubfile\""
  fi
  if grep -Pqs -- "^\\h*net\\.ipv6\\.conf\\.all\\.disable_ipv6\\h*=\\h*1\\h*(#.*)?$" $searchloc && \
      grep -Pqs -- "^\\h*net\\.ipv6\\.conf\\.default\\.disable_ipv6\\h*=\\h*1\\h*(#.*)?$" $searchloc && \
      sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\\h*net\\.ipv6\\.conf\\.all\\.disable_ipv6\\h*=\\h*1\\h*(#.*)?$" && \
      sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\\h*net\\.ipv6\\.conf\\.default\\.disable_ipv6\\h*=\\h*1\\h*(#.*)?$"; then
      [ -n "$output" ] && output="$output, and in sysctl config" || output="ipv6 disabled in sysctl config"
  fi
  [ -n "$output" ] && echo -e "\\n$output\\n" || echo -e "\\nIPv6 is enabled on the system\\n"
}
check_ipv6
)"').stdout

uid_min = login_defs.UID_MIN

audit_tools_files = ['/sbin/auditctl', '/sbin/aureport', '/sbin/ausearch', '/sbin/autrace', '/sbin/auditd', '/sbin/augenrules']

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1.1_Ensure_cramfs_kernel_module_is_not_available' do
  title 'Ensure cramfs kernel module is not available'
  desc  "
    The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.

    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  module_name = 'cramfs'
  if kernel_module(module_name).version.nil?
    describe "Kernel Module #{module_name}" do
      it 'is expected to not exist' do
        expect(kernel_module(module_name).version).to(eq nil)
      end
    end
  else
    describe kernel_module(module_name) do
      it { should_not be_loaded }
      it { should be_disabled }
      it { should be_blacklisted }
    end
    files = command('find /lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf -type f').stdout.split
    files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/^\s*blacklist\s+#{module_name}\s*$/) }
    describe 'Files in which correct configuration is present' do
      it { expect(files_with_correct_conf).not_to(be_empty) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1.2_Ensure_freevxfs_kernel_module_is_not_available' do
  title 'Ensure freevxfs kernel module is not available'
  desc  "
    The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the primary filesystem type for HP-UX operating systems.

    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  module_name = 'freevxfs'
  if kernel_module(module_name).version.nil?
    describe "Kernel Module #{module_name}" do
      it 'is expected to not exist' do
        expect(kernel_module(module_name).version).to(eq nil)
      end
    end
  else
    describe kernel_module(module_name) do
      it { should_not be_loaded }
      it { should be_disabled }
      it { should be_blacklisted }
    end
    files = command('find /lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf -type f').stdout.split
    files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/^\s*blacklist\s+#{module_name}\s*$/) }
    describe 'Files in which correct configuration is present' do
      it { expect(files_with_correct_conf).not_to(be_empty) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1.3_Ensure_hfs_kernel_module_is_not_available' do
  title 'Ensure hfs kernel module is not available'
  desc  "
    The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems.

    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  module_name = 'hfs'
  if kernel_module(module_name).version.nil?
    describe "Kernel Module #{module_name}" do
      it 'is expected to not exist' do
        expect(kernel_module(module_name).version).to(eq nil)
      end
    end
  else
    describe kernel_module(module_name) do
      it { should_not be_loaded }
      it { should be_disabled }
      it { should be_blacklisted }
    end
    files = command('find /lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf -type f').stdout.split
    files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/^\s*blacklist\s+#{module_name}\s*$/) }
    describe 'Files in which correct configuration is present' do
      it { expect(files_with_correct_conf).not_to(be_empty) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1.4_Ensure_hfsplus_kernel_module_is_not_available' do
  title 'Ensure hfsplus kernel module is not available'
  desc  "
    The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows you to mount Mac OS filesystems.

    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  module_name = 'hfsplus'
  if kernel_module(module_name).version.nil?
    describe "Kernel Module #{module_name}" do
      it 'is expected to not exist' do
        expect(kernel_module(module_name).version).to(eq nil)
      end
    end
  else
    describe kernel_module(module_name) do
      it { should_not be_loaded }
      it { should be_disabled }
      it { should be_blacklisted }
    end
    files = command('find /lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf -type f').stdout.split
    files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/^\s*blacklist\s+#{module_name}\s*$/) }
    describe 'Files in which correct configuration is present' do
      it { expect(files_with_correct_conf).not_to(be_empty) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1.5_Ensure_jffs2_kernel_module_is_not_available' do
  title 'Ensure jffs2 kernel module is not available'
  desc  "
    The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.

    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  module_name = 'jffs2'
  if kernel_module(module_name).version.nil?
    describe "Kernel Module #{module_name}" do
      it 'is expected to not exist' do
        expect(kernel_module(module_name).version).to(eq nil)
      end
    end
  else
    describe kernel_module(module_name) do
      it { should_not be_loaded }
      it { should be_disabled }
      it { should be_blacklisted }
    end
    files = command('find /lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf -type f').stdout.split
    files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/^\s*blacklist\s+#{module_name}\s*$/) }
    describe 'Files in which correct configuration is present' do
      it { expect(files_with_correct_conf).not_to(be_empty) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1.8_Ensure_usb-storage_kernel_module_is_not_available' do
  title 'Ensure usb-storage kernel module is not available'
  desc  "
    USB storage provides a means to transfer and store files ensuring persistence and availability of the files independent of network connection status.  Its popularity and utility has led to USB-based malware being a simple and common means for network infiltration and a first step to establishing a persistent threat within a networked environment.

    Rationale: Restricting USB access on the system will decrease the physical attack surface for a device and diminish the possible vectors to introduce malware.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid=0\(root\)/ }
  module_name = 'usb_storage'
  if kernel_module(module_name).version.nil?
    describe "Kernel Module #{module_name}" do
      it 'is expected to not exist' do
        expect(kernel_module(module_name).version).to(eq nil)
      end
    end
  else
    describe kernel_module(module_name) do
      it { should_not be_loaded }
      it { should be_disabled }
      it { should be_blacklisted }
    end
    files = command('find /lib/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf /run/modprobe.d/*.conf /etc/modprobe.d/*.conf -type f').stdout.split
    files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/^\s*blacklist\s+#{module_name}\s*$/) }
    describe 'Files in which correct configuration is present' do
      it { expect(files_with_correct_conf).not_to(be_empty) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.1.1_Ensure_tmp_is_a_separate_partition' do
  title 'Ensure /tmp is a separate partition'
  desc  "
    The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.

    **- IF -** an entry for /tmp exists in /etc/fstab it will take precedence over entries in systemd default unit file.

    **Note:** In an environment where the main system is diskless and connected to iSCSI, entries in /etc/fstab may not take precedence.

    /tmp can be configured to use tmpfs .

    tmpfs puts everything into the kernel internal caches and grows and shrinks to accommodate the files it contains and is able to swap unneeded pages out to swap space. It has maximum size limits which can be adjusted on the fly via mount -o remount .

    Since tmpfs lives completely in the page cache and on swap, all tmpfs pages will be shown as \"Shmem\" in /proc/meminfo and \"Shared\" in free . Notice that these counters also include shared memory. The most reliable way to get the count is using df and du .

    tmpfs has three mount options for sizing:

    * size : The limit of allocated bytes for this tmpfs instance. The default is half of your physical RAM without swap. If you oversize your tmpfs instances the machine will deadlock since the OOM handler will not be able to free that memory.
    * nr_blocks : The same as size, but in blocks of PAGE_SIZE.
    * nr_inodes : The maximum number of inodes for this instance. The default is half of the number of your physical RAM pages, or (on a machine with highmem) the number of lowmem RAM pages, whichever is the lower.
    These parameters accept a suffix k, m or g and can be changed on remount. The size parameter also accepts a suffix % to limit this tmpfs instance to that percentage of your physical RAM. The default, when neither size nor nr_blocks is specified, is size=50% .

    Rationale: Making /tmp its own file system allows an administrator to set additional mount options such as the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to a system setuid program and wait for it to be updated. Once the program was updated, the hard link would be broken, and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.

    This can be accomplished by either mounting tmpfs to /tmp , or creating a separate partition for /tmp .
  "
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
  end
  describe service('tmp.mount') do
    its('params.UnitFileState') { should_not eq 'masked' }
    its('params.UnitFileState') { should_not eq 'disabled' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.1.2_Ensure_nodev_option_set_on_tmp_partition' do
  title 'Ensure nodev option set on /tmp partition'
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.

    Rationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /tmp .
  "
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.1.3_Ensure_nosuid_option_set_on_tmp_partition' do
  title 'Ensure nosuid option set on /tmp partition'
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.

    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /tmp .
  "
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.1.4_Ensure_noexec_option_set_on_tmp_partition' do
  title 'Ensure noexec option set on /tmp partition'
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.

    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp .
  "
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.2.1_Ensure_devshm_is_a_separate_partition' do
  title 'Ensure /dev/shm is a separate partition'
  desc  "
    The /dev/shm directory is a world-writable directory that can function as shared memory that facilitates inter process communication (IPC).

    Rationale: Making /dev/shm its own file system allows an administrator to set additional mount options such as the noexec option on the mount, making /dev/shm useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to a system setuid program and wait for it to be updated. Once the program was updated, the hard link would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.

    This can be accomplished by mounting tmpfs to /dev/shm .
  "
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.2.2_Ensure_nodev_option_set_on_devshm_partition' do
  title 'Ensure nodev option set on /dev/shm partition'
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.

    Rationale: Since the /dev/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions.
  "
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.2.3_Ensure_nosuid_option_set_on_devshm_partition' do
  title 'Ensure nosuid option set on /dev/shm partition'
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.

    Rationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.
  "
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.2.4_Ensure_noexec_option_set_on_devshm_partition' do
  title 'Ensure noexec option set on /dev/shm partition'
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.

    Rationale: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.
  "
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.3.2_Ensure_nodev_option_set_on_home_partition' do
  title 'Ensure nodev option set on /home partition'
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.

    Rationale: Since the /home filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /home .
  "
  impact 1.0
  describe mount('/home') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.3.3_Ensure_nosuid_option_set_on_home_partition' do
  title 'Ensure nosuid option set on /home partition'
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.

    Rationale: Since the /home filesystem is only intended for user file storage, set this option to ensure that users cannot create setuid files in /home .
  "
  impact 1.0
  describe mount('/home') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.4.2_Ensure_nodev_option_set_on_var_partition' do
  title 'Ensure nodev option set on /var partition'
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.

    Rationale: Since the /var filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var .
  "
  impact 1.0
  describe mount('/var') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.4.3_Ensure_nosuid_option_set_on_var_partition' do
  title 'Ensure nosuid option set on /var partition'
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.

    Rationale: Since the /var filesystem is only intended for variable files such as logs, set this option to ensure that users cannot create setuid files in /var .
  "
  impact 1.0
  describe mount('/var') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.5.2_Ensure_nodev_option_set_on_vartmp_partition' do
  title 'Ensure nodev option set on /var/tmp partition'
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.

    Rationale: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var/tmp .
  "
  impact 1.0
  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.5.3_Ensure_nosuid_option_set_on_vartmp_partition' do
  title 'Ensure nosuid option set on /var/tmp partition'
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.

    Rationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp .
  "
  impact 1.0
  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.5.4_Ensure_noexec_option_set_on_vartmp_partition' do
  title 'Ensure noexec option set on /var/tmp partition'
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.

    Rationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp .
  "
  impact 1.0
  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.6.2_Ensure_nodev_option_set_on_varlog_partition' do
  title 'Ensure nodev option set on /var/log partition'
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.

    Rationale: Since the /var/log filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var/log .
  "
  impact 1.0
  describe mount('/var/log') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.6.3_Ensure_nosuid_option_set_on_varlog_partition' do
  title 'Ensure nosuid option set on /var/log partition'
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.

    Rationale: Since the /var/log filesystem is only intended for log files, set this option to ensure that users cannot create setuid files in /var/log .
  "
  impact 1.0
  describe mount('/var/log') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.6.4_Ensure_noexec_option_set_on_varlog_partition' do
  title 'Ensure noexec option set on /var/log partition'
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.

    Rationale: Since the /var/log filesystem is only intended for log files, set this option to ensure that users cannot run executable binaries from /var/log .
  "
  impact 1.0
  describe mount('/var/log') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.7.2_Ensure_nodev_option_set_on_varlogaudit_partition' do
  title 'Ensure nodev option set on /var/log/audit partition'
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.

    Rationale: Since the /var/log/audit filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var/log/audit .
  "
  impact 1.0
  describe mount('/var/log/audit') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.7.3_Ensure_nosuid_option_set_on_varlogaudit_partition' do
  title 'Ensure nosuid option set on /var/log/audit partition'
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.

    Rationale: Since the /var/log/audit filesystem is only intended for variable files such as logs, set this option to ensure that users cannot create setuid files in /var/log/audit .
  "
  impact 1.0
  describe mount('/var/log/audit') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.1.2.7.4_Ensure_noexec_option_set_on_varlogaudit_partition' do
  title 'Ensure noexec option set on /var/log/audit partition'
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.

    Rationale: Since the /var/log/audit filesystem is only intended for audit logs, set this option to ensure that users cannot run executable binaries from /var/log/audit .
  "
  impact 1.0
  describe mount('/var/log/audit') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.2.1.1_Ensure_GPG_keys_are_configured' do
  title 'Ensure GPG keys are configured'
  desc  "
    Most package managers implement GPG key signing to verify package integrity during installation.

    Rationale: It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system.
  "
  impact 0.0
  describe 'This recommendation cannot be checked automatically' do
    skip('This recommendation requires manual review -
    Verify GPG keys are configured correctly for your package manager:
    # apt-key list')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.2.1.2_Ensure_package_manager_repositories_are_configured' do
  title 'Ensure package manager repositories are configured'
  desc  "
    Systems need to have package manager repositories configured to ensure they receive the latest patches and updates.

    Rationale: If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software.
  "
  impact 0.0
  describe 'This recommendation cannot be checked automatically' do
    skip('This recommendation requires manual review -
    Run the following command and verify package repositories are configured correctly:
    # apt-cache policy')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.2.2.1_Ensure_updates_patches_and_additional_security_software_are_installed' do
  title 'Ensure updates, patches, and additional security software are installed'
  desc  "
    Periodically patches are released for included software either due to security flaws or to include additional functionality.

    Rationale: Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected.
  "
  impact 0.0
  describe 'This recommendation cannot be checked automatically' do
    skip('This recommendation requires manual review -
    Verify there are no updates or patches to install:
    # apt update
    # apt -s upgrade')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.3.1.1_Ensure_AppArmor_is_installed' do
  title 'Ensure AppArmor is installed'
  desc  "
    AppArmor provides Mandatory Access Controls.

    Rationale: Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available.
  "
  impact 1.0
  describe package('apparmor') do
    it { should be_installed }
  end
  describe package('apparmor-utils') do
    it { should be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.3.1.2_Ensure_AppArmor_is_enabled_in_the_bootloader_configuration' do
  title 'Ensure AppArmor is enabled in the bootloader configuration'
  desc  "
    Configure AppArmor to be enabled at boot time and verify that it has not been overwritten by the bootloader boot parameters.

    **Note: This recommendation is designed around the grub bootloader, if LILO or another bootloader is in use in your environment enact equivalent settings.**

    Rationale: AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe file('/boot/grub/grub.cfg') do
    its('content') { should match(/^[^#]\s*linux.*$/) }
  end
  file('/boot/grub/grub.cfg').content.to_s.scan(/^[^#]\s*linux.*$/).flatten.each do |entry|
    describe entry do
      it { should match(/apparmor=1/) }
      it { should match(/security=apparmor/) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.3.1.3_Ensure_all_AppArmor_Profiles_are_in_enforce_or_complain_mode' do
  title 'Ensure all AppArmor Profiles are in enforce or complain mode'
  desc  "
    AppArmor profiles define what resources applications are able to access.

    Rationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  profiles_loaded = command("apparmor_status | awk '/profiles\s+are\s+loaded/ {print $1}'").stdout.to_i
  profiles_in_enforce_mode = command("apparmor_status | awk '/profiles\s+are\s+in\s+enforce\s+mode/ {print $1}'").stdout.to_i
  profiles_in_complain_mode = command("apparmor_status | awk '/profiles\s+are\s+in\s+complain\s+mode/ {print $1}'").stdout.to_i
  unconfined_processes = command("apparmor_status | awk '/processes\s+are\s+unconfined\s+but\s+have\s+a\s+profile\s+defined/ {print $1}'").stdout.to_i
  profiles_in_enforce_mode_or_complain_mode = profiles_in_enforce_mode + profiles_in_complain_mode

  if profiles_loaded > 0
    describe 'No processes should be unconfined.' do
      it 'Expected no unconfined processes' do
        expect(unconfined_processes).to eq 0
      end
    end
    describe 'All profiles should be in enforce or complain mode.' do
      it 'Expected profiles in enforce or complain mode' do
        expect(profiles_in_enforce_mode_or_complain_mode).to eq profiles_loaded
      end
    end
  else
    describe 'No profiles are loaded.' do
      it 'Expected profiles loaded to not be empty' do
        expect(profiles_loaded).to be > 0
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.4.1_Ensure_bootloader_password_is_set' do
  title 'Ensure bootloader password is set'
  desc  "
    Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters

    Rationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off AppArmor at boot time).
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe.one do
    describe file('/boot/grub/grub.cfg') do
      its('content') { should match(/^\s*set\s+superusers\s*=\s*\"?\S+\b/) }
      its('content') { should match(/^\s*password_pbkdf2\s+\S+\s+\S+\b/) }
    end
    describe package('grub-common') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.4.2_Ensure_access_to_bootloader_config_is_configured' do
  title 'Ensure access to bootloader config is configured'
  desc  "
    The grub configuration file contains information on boot settings and passwords for unlocking boot options.

    Rationale: Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them.
  "
  impact 1.0
  describe file('/boot/grub/grub.cfg') do
    it { should_not be_more_permissive_than('0600') }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.5.1_Ensure_address_space_layout_randomization_is_enabled' do
  title 'Ensure address space layout randomization is enabled'
  desc  "
    Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.

    Rationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting.
  "
  impact 1.0
  tag cci: 'CCI-000366: The organization implements the security configuration settings'
  describe bash("\na_output=(); a_output2=(); l_ipv6_disabled=\"\"\nl_ufw_sysctl_file=\"$([ -f /etc/default/ufw ] && awk -F= '/^\\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)\"\nl_analyze_cmd=\"$(readlink -f /lib/systemd/systemd-sysctl)\"\n\n# Function to check if IPv6 is enabled\nf_ipv6_chk()\n{\n   l_ipv6_disabled=\"no\"\n   ! grep -Pqs -- '^\\s*0\\b' /sys/module/ipv6/parameters/disable && l_ipv6_disabled=\"yes\"\n   if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- \"^\\s*net\\.ipv6\\.conf\\.all\\.disable_ipv6\\s*=\\s*1\\b\" && \\\n      sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- \"^\\s*net\\.ipv6\\.conf\\.default\\.disable_ipv6\\s*=\\s*1\\b\"; then\n      l_ipv6_disabled=\"yes\"\n   fi\n}\n\n# Function to check kernel parameter values \nf_kernel_parameter_chk()\n{\n   # Check kernel parameter in the running configuration\n   l_running_parameter_value=\"$(sysctl \"$l_parameter_name\" | awk -F= '{print $2}' | xargs)\"\n   if grep -Pq -- '\\b'\"$l_parameter_value\"'\\b' <<< \"$l_running_parameter_value\"; then\n      a_output+=(\"  - Parameter: \\\"$l_parameter_name\\\"\" \\\n      \"    correctly set to \\\"$l_running_parameter_value\\\" in the running configuration\")\n   else\n      a_output2+=(\"  - Parameter: \\\"$l_parameter_name\\\"\" \\\n      \"    is incorrectly set to \\\"$l_running_parameter_value\\\" in the running configuration\" \\\n      \"    Should be set to: \\\"$l_value_out\\\"\")\n   fi\n\n   # Check kernel parameter value loaded from the configuration files\n   l_used_parameter_setting=\"$(grep -PHs -- '^\\s*'\"$l_parameter_name\"'\\b' \"$l_ufw_sysctl_file\" | tail -n 1)\"\n   if [ -z \"$l_used_parameter_setting\" ]; then\n      while IFS= read -r l_file; do\n         l_file=\"$(tr -d '# ' <<< \"$l_file\")\"\n         l_used_parameter_setting=\"$(grep -PHs -- '^\\s*'\"$l_parameter_name\"'\\b' \"$l_file\" | tail -n 1)\"\n         [ -n \"$l_used_parameter_setting\" ] && break\n      done < <($l_analyze_cmd --cat-config | tac | grep -Pio '^\\s*#\\s*\\/[^#\\n\\r\\s]+\\.conf\\b')\n   fi\n   if [ -n \"$l_used_parameter_setting\" ]; then\n      while IFS=: read -r l_file_name l_file_parameter; do\n         while IFS=\"=\" read -r l_file_parameter_name l_file_parameter_value; do\n            if grep -Pq -- \"$l_parameter_value\" <<< \"$l_file_parameter_value\"; then\n               a_output+=(\"  - Parameter: \\\"${l_file_parameter_name// }\\\"\" \\\n               \"    correctly set to: \\\"${l_file_parameter_value// }\\\" in the file: \\\"$l_file_name\\\"\")\n            else\n               a_output2+=(\"  - Parameter: \\\"${l_file_parameter_name// }\\\"\" \\\n               \"    incorrectly set to: \\\"${l_file_parameter_value// }\\\" in the file: \\\"$l_file_name\\\"\" \\\n               \"    Should be set to: \\\"$l_value_out\\\"\")\n            fi\n         done <<< \"$l_file_parameter\"\n      done <<< \"$l_used_parameter_setting\"\n   else\n      a_output2+=(\"  - Parameter: \\\"$l_parameter_name\\\" is not set in an included file\" \\\n      \"  *** Note: \\\"$l_parameter_name\\\" May be set in a file that's ignored by load procedure ***\")\n   fi\n}\n\nwhile IFS=\"=\" read -r l_parameter_name l_parameter_value; do # Check parameters\n   l_parameter_name=\"${l_parameter_name// /}\"; l_parameter_value=\"${l_parameter_value// /}\"\n   l_value_out=\"${l_parameter_value//-/ through }\"; l_value_out=\"${l_value_out//|/ or }\"\n   l_value_out=\"$(tr -d '(){}' <<< \"$l_value_out\")\"\n   if grep -q '^net.ipv6.' <<< \"$l_parameter_name\"; then\n      [ -z \"$l_ipv6_disabled\" ] && f_ipv6_chk\n      if [ \"$l_ipv6_disabled\" = \"yes\" ]; then\n         a_output+=(\" - IPv6 is disabled on the system, \\\"$l_parameter_name\\\" is not applicable\")\n      else\n         f_kernel_parameter_chk\n      fi\n   else\n      f_kernel_parameter_chk\n   fi\ndone <<< \"kernel.randomize_va_space=2\"\n\n# Send test results and output to CIS-CAT\nif [ \"${#a_output2[@]}\" -le 0 ]; then\n   printf '%s\\n' \"\" \"- Audit Result:\" \"  ** PASS **\" \"${a_output[@]}\" \"\"\n   else\n   printf '%s\\n' \"\" \"- Audit Result:\" \"  ** FAIL **\" \" - Reason(s) for audit failure:\" \"${a_output2[@]}\"\n   [ \"${#a_output[@]}\" -gt 0 ] && printf '%s\\n' \"\" \"- Correctly set:\" \"${a_output[@]}\" \"\"\n   fi").stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.5.2_Ensure_ptrace_scope_is_restricted' do
  title 'Ensure ptrace_scope is restricted'
  desc  "
    The ptrace() system call provides a means by which one process (the \"tracer\") may observe and control the execution of another process (the \"tracee\"), and examine and change the tracee's memory and registers.

    Rationale: If one application is compromised, it would be possible for an attacker to attach to other running processes (e.g. Bash, Firefox, SSH sessions, GPG agent, etc) to extract additional credentials and continue to expand the scope of their attack.

    Enabling restricted mode will limit the ability of a compromised process to PTRACE_ATTACH on other processes running under the same user. With restricted mode, ptrace will continue to work with root user.
  "
  impact 1.0
  describe bash("\na_output=(); a_output2=(); l_ipv6_disabled=\"\"\nl_ufw_sysctl_file=\"$([ -f /etc/default/ufw ] && awk -F= '/^\\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)\"\nl_analyze_cmd=\"$(readlink -f /lib/systemd/systemd-sysctl)\"\n\n# Function to check if IPv6 is enabled\nf_ipv6_chk()\n{\n   l_ipv6_disabled=\"no\"\n   ! grep -Pqs -- '^\\s*0\\b' /sys/module/ipv6/parameters/disable && l_ipv6_disabled=\"yes\"\n   if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- \"^\\s*net\\.ipv6\\.conf\\.all\\.disable_ipv6\\s*=\\s*1\\b\" && \\\n      sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- \"^\\s*net\\.ipv6\\.conf\\.default\\.disable_ipv6\\s*=\\s*1\\b\"; then\n      l_ipv6_disabled=\"yes\"\n   fi\n}\n\n# Function to check kernel parameter values \nf_kernel_parameter_chk()\n{\n   # Check kernel parameter in the running configuration\n   l_running_parameter_value=\"$(sysctl \"$l_parameter_name\" | awk -F= '{print $2}' | xargs)\"\n   if grep -Pq -- '\\b'\"$l_parameter_value\"'\\b' <<< \"$l_running_parameter_value\"; then\n      a_output+=(\"  - Parameter: \\\"$l_parameter_name\\\"\" \\\n      \"    correctly set to \\\"$l_running_parameter_value\\\" in the running configuration\")\n   else\n      a_output2+=(\"  - Parameter: \\\"$l_parameter_name\\\"\" \\\n      \"    is incorrectly set to \\\"$l_running_parameter_value\\\" in the running configuration\" \\\n      \"    Should be set to: \\\"$l_value_out\\\"\")\n   fi\n\n   # Check kernel parameter value loaded from the configuration files\n   l_used_parameter_setting=\"$(grep -PHs -- '^\\s*'\"$l_parameter_name\"'\\b' \"$l_ufw_sysctl_file\" | tail -n 1)\"\n   if [ -z \"$l_used_parameter_setting\" ]; then\n      while IFS= read -r l_file; do\n         l_file=\"$(tr -d '# ' <<< \"$l_file\")\"\n         l_used_parameter_setting=\"$(grep -PHs -- '^\\s*'\"$l_parameter_name\"'\\b' \"$l_file\" | tail -n 1)\"\n         [ -n \"$l_used_parameter_setting\" ] && break\n      done < <($l_analyze_cmd --cat-config | tac | grep -Pio '^\\s*#\\s*\\/[^#\\n\\r\\s]+\\.conf\\b')\n   fi\n   if [ -n \"$l_used_parameter_setting\" ]; then\n      while IFS=: read -r l_file_name l_file_parameter; do\n         while IFS=\"=\" read -r l_file_parameter_name l_file_parameter_value; do\n            if grep -Pq -- \"$l_parameter_value\" <<< \"$l_file_parameter_value\"; then\n               a_output+=(\"  - Parameter: \\\"${l_file_parameter_name// }\\\"\" \\\n               \"    correctly set to: \\\"${l_file_parameter_value// }\\\" in the file: \\\"$l_file_name\\\"\")\n            else\n               a_output2+=(\"  - Parameter: \\\"${l_file_parameter_name// }\\\"\" \\\n               \"    incorrectly set to: \\\"${l_file_parameter_value// }\\\" in the file: \\\"$l_file_name\\\"\" \\\n               \"    Should be set to: \\\"$l_value_out\\\"\")\n            fi\n         done <<< \"$l_file_parameter\"\n      done <<< \"$l_used_parameter_setting\"\n   else\n      a_output2+=(\"  - Parameter: \\\"$l_parameter_name\\\" is not set in an included file\" \\\n      \"  *** Note: \\\"$l_parameter_name\\\" May be set in a file that's ignored by load procedure ***\")\n   fi\n}\n\nwhile IFS=\"=\" read -r l_parameter_name l_parameter_value; do # Check parameters\n   l_parameter_name=\"${l_parameter_name// /}\"; l_parameter_value=\"${l_parameter_value// /}\"\n   l_value_out=\"${l_parameter_value//-/ through }\"; l_value_out=\"${l_value_out//|/ or }\"\n   l_value_out=\"$(tr -d '(){}' <<< \"$l_value_out\")\"\n   if grep -q '^net.ipv6.' <<< \"$l_parameter_name\"; then\n      [ -z \"$l_ipv6_disabled\" ] && f_ipv6_chk\n      if [ \"$l_ipv6_disabled\" = \"yes\" ]; then\n         a_output+=(\" - IPv6 is disabled on the system, \\\"$l_parameter_name\\\" is not applicable\")\n      else\n         f_kernel_parameter_chk\n      fi\n   else\n      f_kernel_parameter_chk\n   fi\ndone <<< \"kernel.yama.ptrace_scope=(1|2|3)\"\n\n# Send test results and output to CIS-CAT\nif [ \"${#a_output2[@]}\" -le 0 ]; then\n   printf '%s\\n' \"\" \"- Audit Result:\" \"  ** PASS **\" \"${a_output[@]}\" \"\"\n   else\n   printf '%s\\n' \"\" \"- Audit Result:\" \"  ** FAIL **\" \" - Reason(s) for audit failure:\" \"${a_output2[@]}\"\n   [ \"${#a_output[@]}\" -gt 0 ] && printf '%s\\n' \"\" \"- Correctly set:\" \"${a_output[@]}\" \"\"\n   fi").stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.5.3_Ensure_core_dumps_are_restricted' do
  title 'Ensure core dumps are restricted'
  desc  "
    A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.

    Rationale: Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5) ). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core.
  "
  impact 1.0
  files = command('find /etc/security/limits.d -type f -regex ^.+$').stdout.split + ['/etc/security/limits.conf']
  describe.one do
    files.each do |file|
      describe file(file) do
        its('content') { should match(/^\s*\*\s+hard\s+core\s+0\b/) }
      end
    end
  end
  describe bash("\na_output=(); a_output2=(); l_ipv6_disabled=\"\"\nl_ufw_sysctl_file=\"$([ -f /etc/default/ufw ] && awk -F= '/^\\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)\"\nl_analyze_cmd=\"$(readlink -f /lib/systemd/systemd-sysctl)\"\n\n# Function to check if IPv6 is enabled\nf_ipv6_chk()\n{\n   l_ipv6_disabled=\"no\"\n   ! grep -Pqs -- '^\\s*0\\b' /sys/module/ipv6/parameters/disable && l_ipv6_disabled=\"yes\"\n   if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- \"^\\s*net\\.ipv6\\.conf\\.all\\.disable_ipv6\\s*=\\s*1\\b\" && \\\n      sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- \"^\\s*net\\.ipv6\\.conf\\.default\\.disable_ipv6\\s*=\\s*1\\b\"; then\n      l_ipv6_disabled=\"yes\"\n   fi\n}\n\n# Function to check kernel parameter values \nf_kernel_parameter_chk()\n{\n   # Check kernel parameter in the running configuration\n   l_running_parameter_value=\"$(sysctl \"$l_parameter_name\" | awk -F= '{print $2}' | xargs)\"\n   if grep -Pq -- '\\b'\"$l_parameter_value\"'\\b' <<< \"$l_running_parameter_value\"; then\n      a_output+=(\"  - Parameter: \\\"$l_parameter_name\\\"\" \\\n      \"    correctly set to \\\"$l_running_parameter_value\\\" in the running configuration\")\n   else\n      a_output2+=(\"  - Parameter: \\\"$l_parameter_name\\\"\" \\\n      \"    is incorrectly set to \\\"$l_running_parameter_value\\\" in the running configuration\" \\\n      \"    Should be set to: \\\"$l_value_out\\\"\")\n   fi\n\n   # Check kernel parameter value loaded from the configuration files\n   l_used_parameter_setting=\"$(grep -PHs -- '^\\s*'\"$l_parameter_name\"'\\b' \"$l_ufw_sysctl_file\" | tail -n 1)\"\n   if [ -z \"$l_used_parameter_setting\" ]; then\n      while IFS= read -r l_file; do\n         l_file=\"$(tr -d '# ' <<< \"$l_file\")\"\n         l_used_parameter_setting=\"$(grep -PHs -- '^\\s*'\"$l_parameter_name\"'\\b' \"$l_file\" | tail -n 1)\"\n         [ -n \"$l_used_parameter_setting\" ] && break\n      done < <($l_analyze_cmd --cat-config | tac | grep -Pio '^\\s*#\\s*\\/[^#\\n\\r\\s]+\\.conf\\b')\n   fi\n   if [ -n \"$l_used_parameter_setting\" ]; then\n      while IFS=: read -r l_file_name l_file_parameter; do\n         while IFS=\"=\" read -r l_file_parameter_name l_file_parameter_value; do\n            if grep -Pq -- \"$l_parameter_value\" <<< \"$l_file_parameter_value\"; then\n               a_output+=(\"  - Parameter: \\\"${l_file_parameter_name// }\\\"\" \\\n               \"    correctly set to: \\\"${l_file_parameter_value// }\\\" in the file: \\\"$l_file_name\\\"\")\n            else\n               a_output2+=(\"  - Parameter: \\\"${l_file_parameter_name// }\\\"\" \\\n               \"    incorrectly set to: \\\"${l_file_parameter_value// }\\\" in the file: \\\"$l_file_name\\\"\" \\\n               \"    Should be set to: \\\"$l_value_out\\\"\")\n            fi\n         done <<< \"$l_file_parameter\"\n      done <<< \"$l_used_parameter_setting\"\n   else\n      a_output2+=(\"  - Parameter: \\\"$l_parameter_name\\\" is not set in an included file\" \\\n      \"  *** Note: \\\"$l_parameter_name\\\" May be set in a file that's ignored by load procedure ***\")\n   fi\n}\n\nwhile IFS=\"=\" read -r l_parameter_name l_parameter_value; do # Check parameters\n   l_parameter_name=\"${l_parameter_name// /}\"; l_parameter_value=\"${l_parameter_value// /}\"\n   l_value_out=\"${l_parameter_value//-/ through }\"; l_value_out=\"${l_value_out//|/ or }\"\n   l_value_out=\"$(tr -d '(){}' <<< \"$l_value_out\")\"\n   if grep -q '^net.ipv6.' <<< \"$l_parameter_name\"; then\n      [ -z \"$l_ipv6_disabled\" ] && f_ipv6_chk\n      if [ \"$l_ipv6_disabled\" = \"yes\" ]; then\n         a_output+=(\" - IPv6 is disabled on the system, \\\"$l_parameter_name\\\" is not applicable\")\n      else\n         f_kernel_parameter_chk\n      fi\n   else\n      f_kernel_parameter_chk\n   fi\ndone <<< \"fs.suid_dumpable=0\"\n\n# Send test results and output to CIS-CAT\nif [ \"${#a_output2[@]}\" -le 0 ]; then\n   printf '%s\\n' \"\" \"- Audit Result:\" \"  ** PASS **\" \"${a_output[@]}\" \"\"\n   else\n   printf '%s\\n' \"\" \"- Audit Result:\" \"  ** FAIL **\" \" - Reason(s) for audit failure:\" \"${a_output2[@]}\"\n   [ \"${#a_output[@]}\" -gt 0 ] && printf '%s\\n' \"\" \"- Correctly set:\" \"${a_output[@]}\" \"\"\n   fi").stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.5.4_Ensure_prelink_is_not_installed' do
  title 'Ensure prelink is not installed'
  desc  "
    prelink is a program that modifies ELF shared libraries and ELF dynamically linked binaries in such a way that the time needed for the dynamic linker to perform relocations at startup significantly decreases.

    Rationale: The prelinking feature can interfere with the operation of AIDE, because it changes binaries. Prelinking can also increase the vulnerability of the system if a malicious user is able to compromise a common library such as libc.
  "
  impact 1.0
  describe package('prelink') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.5.5_Ensure_Automatic_Error_Reporting_is_not_enabled' do
  title 'Ensure Automatic Error Reporting is not enabled'
  desc  "
    The Apport Error Reporting Service automatically generates crash reports for debugging

    Rationale: Apport collects potentially sensitive data, such as core dumps, stack traces, and log files. They can contain passwords, credit card numbers, serial numbers, and other private material.
  "
  impact 1.0
  if package('apport').installed?
    describe file('/etc/default/apport') do
      its('content') { should match(/^\s*enabled\s*=\s*0\b/) }
    end
    describe service('apport').params do
      its('ActiveState') { should_not eq 'active' }
    end
  else
    describe package('apport') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.6.1_Ensure_message_of_the_day_is_configured_properly' do
  title 'Ensure message of the day is configured properly'
  desc  "
    The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.

    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version

    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in.
  "
  impact 1.0
  describe command("grep -Ei \"(\\\\\\v|\\\\\\r|\\\\\\m|\\\\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/motd") do
    its('stdout') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.6.2_Ensure_local_login_warning_banner_is_configured_properly' do
  title 'Ensure local login warning banner is configured properly'
  desc  "
    The contents of the /etc/issue file are displayed to users prior to login for local terminals.

    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version - or the operating system's name

    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in.
  "
  impact 1.0
  describe file('/etc/issue') do
    its('content') { should match(/^.+$/) }
  end
  describe command("grep -Ei \"(\\\\\\v|\\\\\\r|\\\\\\m|\\\\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue") do
    its('stdout') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.6.3_Ensure_remote_login_warning_banner_is_configured_properly' do
  title 'Ensure remote login warning banner is configured properly'
  desc  "
    The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.

    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version

    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in.
  "
  impact 1.0
  describe file('/etc/issue.net') do
    its('content') { should match(/^.+$/) }
  end
  describe command("grep -Ei \"(\\\\\\v|\\\\\\r|\\\\\\m|\\\\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue.net") do
    its('stdout') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.6.4_Ensure_access_to_etcmotd_is_configured' do
  title 'Ensure access to /etc/motd is configured'
  desc  "
    The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.

    Rationale: **- IF -** the /etc/motd file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.
  "
  impact 1.0
  if file('/etc/motd').exist?
    describe file('/etc/motd') do
      it { should exist }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
      it { should_not be_more_permissive_than('0644') }
    end
  else
    describe file('/etc/motd') do
      it { should_not exist }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.6.5_Ensure_access_to_etcissue_is_configured' do
  title 'Ensure access to /etc/issue is configured'
  desc  "
    The contents of the /etc/issue file are displayed to users prior to login for local terminals.

    Rationale: **- IF -** the /etc/issue file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.
  "
  impact 1.0
  describe file('/etc/issue') do
    it { should exist }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
    it { should_not be_more_permissive_than('0644') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.6.6_Ensure_access_to_etcissue.net_is_configured' do
  title 'Ensure access to /etc/issue.net is configured'
  desc  "
    The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.

    Rationale: **- IF -** the /etc/issue.net file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.
  "
  impact 1.0
  describe file('/etc/issue.net') do
    it { should exist }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
    it { should_not be_more_permissive_than('0644') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.2_Ensure_GDM_login_banner_is_configured' do
  title 'Ensure GDM login banner is configured'
  desc  "
    GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.

    Rationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    output = bash("l_output=\"\" l_output2=\"\"\n# Look for existing settings and set variables if they exist\nl_gdmfile=\"$(grep -Prils '^\\h*banner-message-enable\\b' /etc/dconf/db/*.d)\"\nif [ -n \"$l_gdmfile\" ]; then\n   # Set profile name based on dconf db directory ({PROFILE_NAME}.d)\n   l_gdmprofile=\"$(awk -F\\/ '{split($(NF-1),a,\".\");print a[1]}' <<< \"$l_gdmfile\")\"\n   # Check if banner message is enabled\n   if grep -Pisq '^\\h*banner-message-enable=true\\b' \"$l_gdmfile\"; then\n      l_output=\"$l_output\\n - The \\\"banner-message-enable\\\" option is enabled in \\\"$l_gdmfile\\\"\"\n   else\n      l_output2=\"$l_output2\\n - The \\\"banner-message-enable\\\" option is not enabled\"\n   fi\n   l_lsbt=\"$(grep -Pios '^\\h*banner-message-text=.*$' \"$l_gdmfile\")\"\n   if [ -n \"$l_lsbt\" ]; then\n      l_output=\"$l_output\\n - The \\\"banner-message-text\\\" option is set in \\\"$l_gdmfile\\\"\\n  - banner-message-text is set to:\\n  - \\\"$l_lsbt\\\"\"\n   else\n      l_output2=\"$l_output2\\n - The \\\"banner-message-text\\\" option is not set\"\n   fi\n   if grep -Pq \"^\\h*system-db:$l_gdmprofile\" /etc/dconf/profile/\"$l_gdmprofile\"; then\n      l_output=\"$l_output\\n - The \\\"$l_gdmprofile\\\" profile exists\"\n   else\n      l_output2=\"$l_output2\\n - The \\\"$l_gdmprofile\\\" profile doesn't exist\"\n   fi\n   if [ -f \"/etc/dconf/db/$l_gdmprofile\" ]; then\n      l_output=\"$l_output\\n - The \\\"$l_gdmprofile\\\" profile exists in the dconf database\"\n   else\n      l_output2=\"$l_output2\\n - The \\\"$l_gdmprofile\\\" profile doesn't exist in the dconf database\"\n   fi\nelse\n   l_output2=\"$l_output2\\n - The \\\"banner-message-enable\\\" option isn't configured\"\nfi\n# Report results. If no failures output in l_output2, we pass\nif [ -z \"$l_output2\" ]; then\n   echo -e \"\\n- Audit Result:\\n  ** PASS **\\n$l_output\\n\"\nelse\n   echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - Reason(s) for audit failure:\\n$l_output2\\n\"\n   [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"\nfi").stdout
    describe output do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.3_Ensure_GDM_disable-user-list_option_is_enabled' do
  title 'Ensure GDM disable-user-list option is enabled'
  desc  "
    GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.

    The disable-user-list option controls if a list of users is displayed on the login screen

    Rationale: Displaying the user list eliminates half of the Userid/Password equation that an unauthorized person would need to log on.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash("\n\noutput=\"\" output2=\"\"\nl_gdmfile=\"$(grep -Pril '^\\h*disable-user-list\\h*=\\h*true\\b' /etc/dconf/db)\"\nif [ -n \"$l_gdmfile\" ]; then\n\toutput=\"$output\\n - The \\\"disable-user-list\\\" option is enabled in \\\"$l_gdmfile\\\"\"\n\tl_gdmprofile=\"$(awk -F\\/ '{split($(NF-1),a,\".\");print a[1]}' <<< \"$l_gdmfile\")\"\n\tif grep -Pq \"^\\h*system-db:$l_gdmprofile\" /etc/dconf/profile/\"$l_gdmprofile\"; then\n\t\toutput=\"$output\\n - The \\\"$l_gdmprofile\\\" exists\"\n\telse\n\t\toutput2=\"$output2\\n - The \\\"$l_gdmprofile\\\" doesn't exist\"\n\tfi\n\tif [ -f \"/etc/dconf/db/$l_gdmprofile\" ]; then\n\t\toutput=\"$output\\n - The \\\"$l_gdmprofile\\\" profile exists in the dconf database\"\n\telse\n\t\toutput2=\"$output2\\n - The \\\"$l_gdmprofile\\\" profile doesn't exist in the dconf database\"\n\tfi\nelse\n\toutput2=\"$output2\\n - The \\\"disable-user-list\\\" option is not enabled\"\nfi\n# Report results. If no failures output in l_output2, we pass\nif [ -z \"$output2\" ]; then\n\techo -e \"\\n- Audit result:\\n   *** PASS: ***\\n$output\\n\"\nelse\n\techo -e \"\\n- Audit Result:\\n   *** FAIL: ***\\n$output2\\n\"\n\t[ -n \"$output\" ] && echo -e \"$output\\n\"\nfi").stdout do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.4_Ensure_GDM_screen_locks_when_the_user_is_idle' do
  title 'Ensure GDM screen locks when the user is idle'
  desc  "
    GNOME Desktop Manager can make the screen lock automatically whenever the user is idle for some amount of time.

    Rationale: Setting a lock-out value reduces the window of opportunity for unauthorized user access to another user's session that has been left unattended.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash('gsettings get org.gnome.desktop.screensaver lock-delay') do
      its('stdout') { should match /^uint32\s+[0-5]$/ }
    end
    describe bash('gsettings get org.gnome.desktop.session idle-delay') do
      its('stdout') { should match /^uint32\s+([1-9]|[1-9]\d|[1-8]\d\d|900)$/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.5_Ensure_GDM_screen_locks_cannot_be_overridden' do
  title 'Ensure GDM screen locks cannot be overridden'
  desc  "
    GNOME Desktop Manager can lock down specific settings by using the lockdown mode in dconf to prevent users from changing specific settings.

    To lock down a dconf key or subpath,  create a locks subdirectory in the keyfile directory. The files inside this directory contain a list of keys or subpaths to lock. Just as with the keyfiles, you may add any number of files to this directory.

    Rationale: Setting a lock-out value reduces the window of opportunity for unauthorized user access to another user's session that has been left unattended.

    Without locking down the system settings, user settings take precedence over the system settings.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash("\n   l_pkgoutput=\"\"\n   if command -v dpkg-query > /dev/null 2>&1; then\n      l_pq=\"dpkg-query -W\"\n   elif command -v rpm > /dev/null 2>&1; then\n      l_pq=\"rpm -q\"\n   fi\n\n   # Check if GDM is installed\n   l_pcl=\"gdm gdm3\" # Space-separated list of packages to check\n   for l_pn in $l_pcl; do\n      $l_pq \"$l_pn\" > /dev/null 2>&1 && l_pkgoutput=\"$l_pkgoutput\\n - Package: \\\"$l_pn\\\" exists on the system\\n - checking configuration\"\n   done\n\n   # Check configuration (If applicable)\n   if [ -n \"$l_pkgoutput\" ]; then\n      l_output=\"\" l_output2=\"\"\n\n      # Check if the idle-delay is locked\n      if grep -Psrilq '^\\h*idle-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/; then\n         if grep -Prilq '\\/org\\/gnome\\/desktop\\/session\\/idle-delay\\b' /etc/dconf/db/*/locks; then\n            l_output=\"$l_output\\n - \\\"idle-delay\\\" is locked\"\n         else\n            l_output2=\"$l_output2\\n - \\\"idle-delay\\\" is not locked\"\n         fi\n      else\n         l_output2=\"$l_output2\\n - \\\"idle-delay\\\" is not set so it cannot be locked\"\n      fi\n\n      # Check if the lock-delay is locked\n      if grep -Psrilq '^\\h*lock-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/; then\n         if grep -Prilq '\\/org\\/gnome\\/desktop\\/screensaver\\/lock-delay\\b' /etc/dconf/db/*/locks; then\n            l_output=\"$l_output\\n - \\\"lock-delay\\\" is locked\"\n         else\n            l_output2=\"$l_output2\\n - \\\"lock-delay\\\" is not locked\"\n         fi\n      else\n         l_output2=\"$l_output2\\n - \\\"lock-delay\\\" is not set so it cannot be locked\"\n      fi\n   else\n      l_output=\"$l_output\\n - GNOME Desktop Manager package is not installed on the system\\n  - Recommendation is not applicable\"\n   fi\n\n   # Report results. If no failures output in l_output2, we pass\n   [ -n \"$l_pkgoutput\" ] && echo -e \"\\n$l_pkgoutput\"\n   if [ -z \"$l_output2\" ]; then\n      echo -e \"\\n- Audit Result:\\n  ** PASS **\\n$l_output\\n\"\n   else\n      echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - Reason(s) for audit failure:\\n$l_output2\\n\"\n      [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"\n   fi\n}\n").stdout do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.6_Ensure_GDM_automatic_mounting_of_removable_media_is_disabled' do
  title 'Ensure GDM automatic mounting of removable media is disabled'
  desc  "
    By default GNOME automatically mounts removable media when inserted as a convenience to the user.

    Rationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash("\nl_output=\"\" l_output2=\"\"\n# Look for existing settings and set variables if they exist\nl_kfile=\"$(grep -Prils -- '^\\h*automount\\b' /etc/dconf/db/*.d)\"\nl_kfile2=\"$(grep -Prils -- '^\\h*automount-open\\b' /etc/dconf/db/*.d)\"\n# Set profile name based on dconf db directory ({PROFILE_NAME}.d)\nif [ -f \"$l_kfile\" ]; then\n   l_gpname=\"$(awk -F\\/ '{split($(NF-1),a,\".\");print a[1]}' <<< \"$l_kfile\")\"\nelif [ -f \"$l_kfile2\" ]; then\n   l_gpname=\"$(awk -F\\/ '{split($(NF-1),a,\".\");print a[1]}' <<< \"$l_kfile2\")\"\nfi\n# If the profile name exist, continue checks\nif [ -n \"$l_gpname\" ]; then\n   l_gpdir=\"/etc/dconf/db/$l_gpname.d\"\n   # Check if profile file exists\n   if grep -Pq -- \"^\\h*system-db:$l_gpname\\b\" /etc/dconf/profile/*; then\n      l_output=\"$l_output\\n - dconf database profile file \\\"$(grep -Pl -- \"^\\h*system-db:$l_gpname\\b\" /etc/dconf/profile/*)\\\" exists\"\n   else\n      l_output2=\"$l_output2\\n - dconf database profile isn't set\"\n   fi\n   # Check if the dconf database file exists\n   if [ -f \"/etc/dconf/db/$l_gpname\" ]; then\n      l_output=\"$l_output\\n - The dconf database \\\"$l_gpname\\\" exists\"\n   else\n      l_output2=\"$l_output2\\n - The dconf database \\\"$l_gpname\\\" doesn't exist\"\n   fi\n   # check if the dconf database directory exists\n   if [ -d \"$l_gpdir\" ]; then\n      l_output=\"$l_output\\n - The dconf directory \\\"$l_gpdir\\\" exitst\"\n   else\n      l_output2=\"$l_output2\\n - The dconf directory \\\"$l_gpdir\\\" doesn't exist\"\n   fi\n   # check automount setting\n   if grep -Pqrs -- '^\\h*automount\\h*=\\h*false\\b' \"$l_kfile\"; then\n      l_output=\"$l_output\\n - \\\"automount\\\" is set to false in: \\\"$l_kfile\\\"\"\n   else\n      l_output2=\"$l_output2\\n - \\\"automount\\\" is not set correctly\"\n   fi\n   # check automount-open setting\n   if grep -Pqs -- '^\\h*automount-open\\h*=\\h*false\\b' \"$l_kfile2\"; then\n      l_output=\"$l_output\\n - \\\"automount-open\\\" is set to false in: \\\"$l_kfile2\\\"\"\n   else\n      l_output2=\"$l_output2\\n - \\\"automount-open\\\" is not set correctly\"\n   fi\nelse\n   # Setings don't exist. Nothing further to check\n   l_output2=\"$l_output2\\n - neither \\\"automount\\\" or \\\"automount-open\\\" is set\"\nfi\n# Report results. If no failures output in l_output2, we pass\nif [ -z \"$l_output2\" ]; then\n   echo -e \"\\n- Audit Result:\\n  ** PASS **\\n$l_output\\n\"\nelse\n   echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - Reason(s) for audit failure:\\n$l_output2\\n\"\n   [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"\nfi").stdout do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.7_Ensure_GDM_disabling_automatic_mounting_of_removable_media_is_not_overridden' do
  title 'Ensure GDM disabling automatic mounting of removable media is not overridden'
  desc  "
    By default GNOME automatically mounts removable media when inserted as a convenience to the user.

    By using the lockdown mode in dconf, you can prevent users from changing specific settings. To lock down a dconf key or subpath, create a locks subdirectory in the keyfile directory. The files inside this directory contain a list of keys or subpaths to lock. Just as with the keyfiles, you may add any number of files to this directory.

    Rationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash("\ncheck_setting() \n{\n #  local section=\"\\[$2\\]\"\n   grep -Psrilq \"^\\s*$1\\s*=\\s*false\\b\" /etc/dconf/db/local.d/locks/* 2> /dev/null && echo \"- \\\"$3\\\" is locked and set to false\" || echo \"- \\\"$3\\\" is not locked or not set to false\" \n}\n\n# Array of settings to check\ndeclare -A settings=(\n   [\"automount\"]=\"org/gnome/desktop/media-handling\"\n   [\"automount-open\"]=\"org/gnome/desktop/media-handling\"\n)\n\n# Check GNOME Desktop Manager configurations\na_output=() a_output2=()\nfor setting in \"${!settings[@]}\"; do\n   result=$(check_setting \"$setting\" \"${settings[$setting]}\" \"$setting\")\n   if [[ $result == *\"is not locked\"* || $result == *\"not set to false\"* ]]; then\n      a_output2+=(\"$result\")\n   else\n      a_output+=(\"$result\")\n   fi\ndone\n\n# Report results\nprintf '%s\\n' \"\" \"- Audit Result:\"\nif [ \"${#a_output2[@]}\" -gt 0 ]; then\n   printf '%s\\n' \"  ** FAIL **\" \" - Reason(s) for audit failure:\" \"${a_output2[@]}\"\n   [ \"${#a_output[@]}\" -gt 0 ] && printf '%s\\n' \"\" \"- Correctly set:\" \"${a_output[@]}\"\nelse\n   printf '%s\\n' \"  ** PASS **\" \"${a_output[@]}\"\nfi").stdout do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.8_Ensure_GDM_autorun-never_is_enabled' do
  title 'Ensure GDM autorun-never is enabled'
  desc  "
    The autorun-never setting allows the GNOME Desktop Display Manager to disable autorun through GDM.

    Rationale: Malware on removable media may taking advantage of Autorun features when the media is inserted into a system and execute.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash("\nl_output=\"\" l_output2=\"\"\n# Look for existing settings and set variables if they exist\nl_kfile=\"$(grep -Prils -- '^\\h*autorun-never\\b' /etc/dconf/db/*.d)\"\n# Set profile name based on dconf db directory ({PROFILE_NAME}.d)\nif [ -f \"$l_kfile\" ]; then\n   l_gpname=\"$(awk -F\\/ '{split($(NF-1),a,\".\");print a[1]}' <<< \"$l_kfile\")\"\nfi\n# If the profile name exist, continue checks\nif [ -n \"$l_gpname\" ]; then\n   l_gpdir=\"/etc/dconf/db/$l_gpname.d\"\n   # Check if profile file exists\n   if grep -Pq -- \"^\\h*system-db:$l_gpname\\b\" /etc/dconf/profile/*; then\n      l_output=\"$l_output\\n - dconf database profile file \\\"$(grep -Pl -- \"^\\h*system-db:$l_gpname\\b\" /etc/dconf/profile/*)\\\" exists\"\n   else\n      l_output2=\"$l_output2\\n - dconf database profile isn't set\"\n   fi\n   # Check if the dconf database file exists\n   if [ -f \"/etc/dconf/db/$l_gpname\" ]; then\n      l_output=\"$l_output\\n - The dconf database \\\"$l_gpname\\\" exists\"\n   else\n      l_output2=\"$l_output2\\n - The dconf database \\\"$l_gpname\\\" doesn't exist\"\n   fi\n   # check if the dconf database directory exists\n   if [ -d \"$l_gpdir\" ]; then\n      l_output=\"$l_output\\n - The dconf directory \\\"$l_gpdir\\\" exitst\"\n   else\n      l_output2=\"$l_output2\\n - The dconf directory \\\"$l_gpdir\\\" doesn't exist\"\n   fi\n   # check autorun-never setting\n   if grep -Pqrs -- '^\\h*autorun-never\\h*=\\h*true\\b' \"$l_kfile\"; then\n      l_output=\"$l_output\\n - \\\"autorun-never\\\" is set to true in: \\\"$l_kfile\\\"\"\n   else\n      l_output2=\"$l_output2\\n - \\\"autorun-never\\\" is not set correctly\"\n   fi\nelse\n   # Settings don't exist. Nothing further to check\n   l_output2=\"$l_output2\\n - \\\"autorun-never\\\" is not set\"\nfi\n# Report results. If no failures output in l_output2, we pass\nif [ -z \"$l_output2\" ]; then\n   echo -e \"\\n- Audit Result:\\n  ** PASS **\\n$l_output\\n\"\nelse\n   echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - Reason(s) for audit failure:\\n$l_output2\\n\"\n   [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"\nfi").stdout do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.9_Ensure_GDM_autorun-never_is_not_overridden' do
  title 'Ensure GDM autorun-never is not overridden'
  desc  "
    The autorun-never setting allows the GNOME Desktop Display Manager to disable autorun through GDM.

    By using the lockdown mode in dconf, you can prevent users from changing specific settings.

    To lock down a dconf key or subpath, create a locks subdirectory in the keyfile directory. The files inside this directory contain a list of keys or subpaths to lock. Just as with the keyfiles, you may add any number of files to this directory.

    Rationale: Malware on removable media may taking advantage of Autorun features when the media is inserted into a system and execute.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash("\n   l_pkgoutput=\"\"\n   if command -v dpkg-query > /dev/null 2>&1; then\n      l_pq=\"dpkg-query -W\"\n   elif command -v rpm > /dev/null 2>&1; then\n      l_pq=\"rpm -q\"\n   fi\n   # Check if GDM is installed\n   l_pcl=\"gdm gdm3\" # Space separated list of packages to check\n   for l_pn in $l_pcl; do\n      $l_pq \"$l_pn\" > /dev/null 2>&1 && l_pkgoutput=\"$l_pkgoutput\\n - Package: \\\"$l_pn\\\" exists on the system\\n - checking configuration\"\n   done\n   # Search /etc/dconf/db/ for [org/gnome/desktop/media-handling] settings)\n    l_desktop_media_handling=$(grep -Psir -- '^\\h*\\[org/gnome/desktop/media-handling\\]' /etc/dconf/db/*)\n    if [[ -n \"$l_desktop_media_handling\" ]]; then\n        l_output=\"\" l_output2=\"\"\n        l_autorun_setting=$(grep -Psir -- '^\\h*autorun-never=true\\b' /etc/dconf/db/local.d/*)\n        # Check for auto-run setting\n        if [[ -n \"$l_autorun_setting\" ]]; then\n            l_output=\"$l_output\\n - \\\"autorun-never\\\" setting found\"\n        else\n            l_output2=\"$l_output2\\n - \\\"autorun-never\\\" setting not found\"\n        fi    \n    else\n         l_output=\"$l_output\\n - [org/gnome/desktop/media-handling] setting not found in /etc/dconf/db/*\"\n    fi         \n\n   # Report results. If no failures output in l_output2, we pass\n\t[ -n \"$l_pkgoutput\" ] && echo -e \"\\n$l_pkgoutput\"\n   if [ -z \"$l_output2\" ]; then\n      echo -e \"\\n- Audit Result:\\n  ** PASS **\\n$l_output\\n\"   else\n      echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - Reason(s) for audit failure:\\n$l_output2\\n\"\n      [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"\n   fi\n}\n").stdout do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.7.10_Ensure_XDCMP_is_not_enabled' do
  title 'Ensure XDCMP is not enabled'
  desc  "
    X Display Manager Control Protocol (XDMCP) is designed to provide authenticated access to display management services for remote displays

    Rationale: XDMCP is inherently insecure.

    * XDMCP is not a ciphered protocol. This may allow an attacker to capture keystrokes entered by a user
    * XDMCP is vulnerable to man-in-the-middle attacks. This may allow an attacker to steal the credentials of legitimate users by impersonating the XDMCP server.
  "
  impact 1.0
  if package('gdm').installed? || package('gdm3').installed?
    describe bash("\nl_output=\"\" l_output2=\"\"\n\nwhile IFS= read -r l_file; do\n   l_out2=\"$(awk '/\\[xdmcp\\]/{ f = 1;next } /\\[/{ f = 0 } f {if (/^\\s*Enable\\s*=\\s*true/) print \"  - The file: \\\"'\"$l_file\"'\\\" includes: \\\"\" $0 \"\\\" in the \\\"[xdmcp]\\\" block\"}' \"$l_file\")\"\n   [ -n \"$l_out2\" ] && l_output2=\"$l_output2\\n$l_out2\"\ndone < <(grep -Psil -- '^\\h*\\[xdmcp\\]' /etc/{gdm3,gdm}/{custom,daemon}.conf)\n\n# If l_output2 is empty, we pass\nif [ -z \"$l_output2\" ]; then\n   l_output=\" - XDCMP is not enabled\"\n   echo -e \"\\n- Audit Result:\\n  ** PASS **\\n - * Correctly configured * :\\n$l_output\\n\"\nelse\n   echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - * Reasons for audit failure * :\\n$l_output2\\n\"\n   [ -n \"$l_output\" ] && echo -e \"- * Correctly configured * :\\n$l_output\\n\"\nfi").stdout do
      it { should match /PASS/ }
    end
  else
    describe package('gdm') do
      it { should_not be_installed }
    end
    describe package('gdm3') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.1_Ensure_autofs_services_are_not_in_use' do
  title 'Ensure autofs services are not in use'
  desc  "
    autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.

    Rationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in the filesystem even if they lacked permissions to mount it themselves.
  "
  impact 1.0
  describe.one do
    describe service('autofs') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe package('autofs') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.2_Ensure_avahi_daemon_services_are_not_in_use' do
  title 'Ensure avahi daemon services are not in use'
  desc  "
    Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.

    Rationale: Automatic discovery of network services is not normally required for system functionality. It is recommended to remove this package to reduce the potential attack surface.
  "
  impact 1.0
  if package('avahi-daemon').installed?
    describe service('avahi-daemon') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe service('avahi-daemon.socket') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('avahi-daemon') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.3_Ensure_dhcp_server_services_are_not_in_use' do
  title 'Ensure dhcp server services are not in use'
  desc  "
    The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses. There are two versions of the DHCP protocol DHCPv4 and DHCPv6 . At startup the server may be started for one or the other via the -4 or -6 arguments.

    Rationale: Unless a system is specifically set up to act as a DHCP server, it is recommended that this package be removed to reduce the potential attack surface.
  "
  impact 1.0
  if package('isc-dhcp-server').installed?
    describe service('isc-dhcp-server') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe service('isc-dhcp-server6') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('isc-dhcp-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.4_Ensure_dns_server_services_are_not_in_use' do
  title 'Ensure dns server services are not in use'
  desc  "
    The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.

    Rationale: Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe.one do
    describe service('bind9') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe package('bind9') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.5_Ensure_dnsmasq_services_are_not_in_use' do
  title 'Ensure dnsmasq services are not in use'
  desc  "
    dnsmasq is a lightweight tool that provides DNS caching, DNS forwarding and DHCP (Dynamic Host Configuration Protocol) services.

    Rationale: Unless a system is specifically designated to act as a DNS caching, DNS forwarding and/or DHCP server, it is recommended that the package be removed to reduce the potential attack surface.
  "
  impact 1.0
  describe.one do
    describe service('dnsmasq') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe package('dnsmasq') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.6_Ensure_ftp_server_services_are_not_in_use' do
  title 'Ensure ftp server services are not in use'
  desc  "
    The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.

    Rationale: FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface.
  "
  impact 1.0
  describe.one do
    describe service('vsftpd') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe package('vsftpd') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.7_Ensure_ldap_server_services_are_not_in_use' do
  title 'Ensure ldap server services are not in use'
  desc  "
    The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.

    Rationale: If the system will not need to act as an LDAP server, it is recommended that the software be removed to reduce the potential attack surface.
  "
  impact 1.0
  describe.one do
    describe service('slapd') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe package('slapd') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.8_Ensure_message_access_server_services_are_not_in_use' do
  title 'Ensure message access server services are not in use'
  desc  "
    dovecot-imapd and dovecot-pop3d are an open source IMAP and POP3 server for Linux based systems.

    Rationale: Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface.

    **Note:** Several IMAP/POP3 servers exist and can use other service names. These should also be audited and the packages removed if not required.
  "
  impact 1.0
  if package('dovecot-imapd').installed? || package('dovecot-pop3d').installed?
    describe service('dovecot') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe service('dovecot.socket') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('dovecot-imapd') do
      it { should_not be_installed }
    end
    describe package('dovecot-pop3d') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.9_Ensure_network_file_system_services_are_not_in_use' do
  title 'Ensure network file system services are not in use'
  desc  "
    The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.

    Rationale: If the system does not export NFS shares, it is recommended that the nfs-kernel-server package be removed to reduce the remote attack surface.
  "
  impact 1.0
  describe.one do
    describe service('nfs-server') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe package('nfs-kernel-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.10_Ensure_nis_server_services_are_not_in_use' do
  title 'Ensure nis server services are not in use'
  desc  "
    The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files. The NIS client ( ypbind ) was used to bind a machine to an NIS server and receive the distributed configuration files.

    Rationale: ypserv.service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that ypserv.service be removed and other, more secure services be used
  "
  impact 1.0
  if package('ypserv').installed?
    describe service('ypserv.service') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('ypserv') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.11_Ensure_print_server_services_are_not_in_use' do
  title 'Ensure print server services are not in use'
  desc  "
    The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.

    Rationale: If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be removed to reduce the potential attack surface.
  "
  impact 1.0
  if package('cups').installed?
    describe service('cups') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe service('cups.socket') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('cups') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.12_Ensure_rpcbind_services_are_not_in_use' do
  title 'Ensure rpcbind services are not in use'
  desc  "
    The rpcbind utility maps RPC services to the ports on which they listen. RPC processes notify rpcbind when they start, registering the ports they are listening on and the RPC program numbers they expect to serve. The client system then contacts rpcbind on the server with a particular RPC program number. The rpcbind.service redirects the client to the proper port number so it can communicate with the requested service.

    Portmapper is an RPC service, which always listens on tcp and udp 111, and is used to map other RPC services (such as nfs, nlockmgr, quotad, mountd, etc.) to their corresponding port number on the server. When a remote host makes an RPC call to that server, it first consults with portmap to determine where the RPC server is listening.

    Rationale: A small request (~82 bytes via UDP) sent to the Portmapper generates a large response (7x to 28x amplification), which makes it a suitable tool for DDoS attacks. If rpcbind is not required, it is recommended to remove rpcbind package to reduce the potential attack surface.
  "
  impact 1.0
  if package('rpcbind').installed?
    describe service('rpcbind') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe service('rpcbind.socket') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('rpcbind') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.13_Ensure_rsync_services_are_not_in_use' do
  title 'Ensure rsync services are not in use'
  desc  "
    The rsync service can be used to synchronize files between systems over network links.

    Rationale: rsync.service presents a security risk as the rsync protocol is unencrypted.

    The rsync package should be removed to reduce the attack area of the system.
  "
  impact 1.0
  if package('rsync').installed?
    describe service('rsync.service') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('rsync') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.14_Ensure_samba_file_server_services_are_not_in_use' do
  title 'Ensure samba file server services are not in use'
  desc  "
    The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Server Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.

    Rationale: If there is no need to mount directories and file systems to Windows systems, then this service should be deleted to reduce the potential attack surface.
  "
  impact 1.0
  if package('samba').installed?
    describe service('smbd.service') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('samba') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.15_Ensure_snmp_services_are_not_in_use' do
  title 'Ensure snmp services are not in use'
  desc  "
    Simple Network Management Protocol (SNMP) is a widely used protocol for monitoring the health and welfare of network equipment, computer equipment and devices like UPSs.

    Net-SNMP is a suite of applications used to implement SNMPv1 (RFC 1157), SNMPv2 (RFCs 1901-1908), and SNMPv3 (RFCs 3411-3418) using both IPv4 and IPv6.

    Support for SNMPv2 classic (a.k.a. \"SNMPv2 historic\" - RFCs 1441-1452) was dropped with the 4.0 release of the UCD-snmp package.

    The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.

    Rationale: The SNMP server can communicate using SNMPv1 , which transmits data in the clear and does not require authentication to execute commands. SNMPv3 replaces the simple/clear text password sharing used in SNMPv2 with more securely encoded parameters. If the the SNMP service is not required, the snmpd package should be removed to reduce the attack surface of the system.

    **Note:** If SNMP is required:

    *  The server should be configured for SNMP v3 only. User Authentication and Message Encryption should be configured.
    *  If SNMP v2 is **absolutely** necessary, modify the community strings' values.
  "
  impact 1.0
  if package('snmpd').installed?
    describe service('snmpd.service') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('snmpd') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.16_Ensure_tftp_server_services_are_not_in_use' do
  title 'Ensure tftp server services are not in use'
  desc  "
    Trivial File Transfer Protocol (TFTP) is a simple protocol for exchanging files between two TCP/IP machines. TFTP servers allow connections from a TFTP Client for sending and receiving files.

    Rationale: Unless there is a need to run the system as a TFTP server, it is recommended that the package be removed to reduce the potential attack surface.

    TFTP does not have built-in encryption, access control or authentication. This makes it very easy for an attacker to exploit TFTP to gain access to files
  "
  impact 1.0
  if package('tftpd-hpa').installed?
    describe service('tftpd-hpa.service') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('tftpd-hpa') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.17_Ensure_web_proxy_server_services_are_not_in_use' do
  title 'Ensure web proxy server services are not in use'
  desc  "
    Squid is a standard proxy server used in many distributions and environments.

    Rationale: Unless a system is specifically set up to act as a proxy server, it is recommended that the squid package be removed to reduce the potential attack surface.

    **Note:** Several HTTP proxy servers exist. These should be checked and removed unless required.
  "
  impact 1.0
  if package('squid').installed?
    describe service('squid') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe service('squid.service') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('squid') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.18_Ensure_web_server_services_are_not_in_use' do
  title 'Ensure web server services are not in use'
  desc  "
    Web servers provide the ability to host web site content.

    Rationale: Unless there is a local site approved requirement to run a web server service on the system, web server packages should be removed to reduce the potential attack surface.
  "
  impact 1.0
  if package('apache2').installed?
    describe service('apache2') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
    describe service('apache2.socket') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('apache2') do
      it { should_not be_installed }
    end
  end
  if package('nginx').installed?
    describe service('nginx') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('nginx') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.19_Ensure_xinetd_services_are_not_in_use' do
  title 'Ensure xinetd services are not in use'
  desc  "
    The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.

    Rationale: Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface.
  "
  impact 1.0
  if package('xinetd').installed?
    describe service('xinetd') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('xinetd') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.21_Ensure_mail_transfer_agent_is_configured_for_local-only_mode' do
  title 'Ensure mail transfer agent is configured for local-only mode'
  desc  "
    Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail.

    Rationale: The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  port_list = [25, 465, 587]
  port_list.each do |port_number|
    describe port(port_number).where { protocol =~ /.*/ && address =~ /^(?!127\.0\.0\.1|::1).*$/ } do
      its('entries') { should be_empty }
    end
  end
  describe parse_config_file('/etc/postfix/main.cf') do
    its('inet_interfaces') { should match(/loopback-only/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.1.22_Ensure_only_approved_services_are_listening_on_a_network_interface' do
  title 'Ensure only approved services are listening on a network interface'
  desc  "
    A network port is identified by its number, the associated IP address, and the type of the communication protocol such as TCP or UDP.

    A listening port is a network port on which an application or process listens on, acting as a communication endpoint.

    Each listening port can be open or closed (filtered) using a firewall. In general terms, an open port is a network port that accepts incoming packets from remote locations.

    Rationale: Services listening on the system pose a potential risk as an attack vector.  These services should be reviewed, and if not required, the service should be stopped, and the package containing the service should be removed.  If required packages have a dependency, the service should be stopped and masked to reduce the attack surface of the system.
  "
  impact 0.0
  describe 'Ensure_only_approved_services_are_listening_on_a_network_interface' do
    skip('Run the following command:
    # ss -plntu
    Review the output to ensure:
    * All services listed are required on the system and approved by local site policy.
    * Both the port and interface the service is listening on are approved by local site policy.
    * If a listed service is not required:
      => Remove the package containing the service
      => - IF - the service\'s package is required for a dependency, stop and mask the service and/or socket')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.2.1_Ensure_NIS_Client_is_not_installed' do
  title 'Ensure NIS Client is not installed'
  desc  "
    The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client was used to bind a machine to an NIS server and receive the distributed configuration files.

    Rationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed.
  "
  impact 1.0
  describe package('nis') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.2.2_Ensure_rsh_client_is_not_installed' do
  title 'Ensure rsh client is not installed'
  desc  "
    The rsh-client package contains the client commands for the rsh services.

    Rationale: These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh-client package removes the clients for rsh , rcp and rlogin .
  "
  impact 1.0
  describe package('rsh-client') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.2.3_Ensure_talk_client_is_not_installed' do
  title 'Ensure talk client is not installed'
  desc  "
    The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client, which allows initialization of talk sessions, is installed by default.

    Rationale: The software presents a security risk as it uses unencrypted protocols for communication.
  "
  impact 1.0
  describe package('talk') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.2.4_Ensure_telnet_client_is_not_installed' do
  title 'Ensure telnet client is not installed'
  desc  "
    The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.

    Rationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions.
  "
  impact 1.0
  describe package('telnet') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.2.5_Ensure_ldap_client_is_not_installed' do
  title 'Ensure ldap client is not installed'
  desc  "
    The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.

    Rationale: If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface.
  "
  impact 1.0
  describe package('ldap-utils') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.2.6_Ensure_ftp_client_is_not_installed' do
  title 'Ensure ftp client is not installed'
  desc  "
    FTP (File Transfer Protocol) is a traditional and widely used standard tool for transferring files between a server and clients over a network, especially where no authentication is necessary (permits anonymous users to connect to a server).

    Rationale: FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be removed to reduce the potential attack surface.
  "
  impact 1.0
  describe package('ftp') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.3.1.1_Ensure_a_single_time_synchronization_daemon_is_in_use' do
  title 'Ensure a single time synchronization daemon is in use'
  desc  "
    System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.

    **Notes:**

    * **On virtual systems where host based time synchronization is available consult your virtualization software documentation and verify that host based synchronization is in use and follows local site policy. In this scenario, this section should be skipped**
    *  Only **one** time synchronization method should be in use on the system. Configuring multiple time synchronization methods could lead to unexpected or unreliable results

    Rationale: Time synchronization is important to support time sensitive security mechanisms and ensures log files have consistent time records across the enterprise, which aids in forensic investigations.
  "
  impact 1.0
  describe.one do
    describe package('ntp') do
      it { should be_installed }
    end
    describe package('chrony') do
      it { should be_installed }
    end
    describe service('systemd-timesyncd') do
      it { should be_enabled }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.3.2.1_Ensure_systemd-timesyncd_configured_with_authorized_timeserver' do
  title 'Ensure systemd-timesyncd configured with authorized timeserver'
  desc  "
    NTP=

    * A space-separated list of NTP server host names or IP addresses. During runtime this list is combined with any per-interface NTP servers acquired from systemd-networkd.service(8). systemd-timesyncd will contact all configured system or per-interface servers in turn, until one responds. When the empty string is assigned, the list of NTP servers is reset, and all prior assignments will have no effect. This setting defaults to an empty list.
    FallbackNTP=

    * A space-separated list of NTP server host names or IP addresses to be used as the fallback NTP servers. Any per-interface NTP servers obtained from systemd-networkd.service(8) take precedence over this setting, as do any servers set via NTP= above. This setting is hence only relevant if no other NTP server information is known. When the empty string is assigned, the list of NTP servers is reset, and all prior assignments will have no effect. If this option is not given, a compiled-in list of NTP servers is used.

    Rationale: Time synchronization is important to support time sensitive security mechanisms and to ensure log files have consistent time records across the enterprise to aid in forensic investigations
  "
  impact 1.0
  systemd_timesyncd_configured_with_authorized_timeserver = bash("#!/usr/bin/env bash\n\n
  {
    l_output=\"\" l_output2=\"\"
    a_parlist=(\"NTP=[^#\\n\\r]+\" \"FallbackNTP=[^#\\n\\r]+\")
    l_systemd_config_file=\"/etc/systemd/timesyncd.conf\" # Main systemd configuration file
    config_file_parameter_chk()
    {
      unset A_out; declare -A A_out # Check config file(s) setting
      while read -r l_out; do
          if [ -n \"$l_out\" ]; then
            if [[ $l_out =~ ^\\s*# ]]; then
                l_file=\"${l_out//# /}\"
            else
                l_systemd_parameter=\"$(awk -F= '{print $1}' <<< \"$l_out\" | xargs)\"
                grep -Piq -- \"^\\h*$l_systemd_parameter_name\\b\" <<< \"$l_systemd_parameter\" && A_out+=([\"$l_systemd_parameter\"]=\"$l_file\")
            fi
          fi
      done < <(/usr/bin/systemd-analyze cat-config \"$l_systemd_config_file\" | grep -Pio '^\\h*([^#\\n\\r]+|#\\h*\\/[^#\\n\\r\\h]+\\.conf\\b)')
      if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
          while IFS=\"=\" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
            l_systemd_file_parameter_name=\"${l_systemd_file_parameter_name// /}\"
            l_systemd_file_parameter_value=\"${l_systemd_file_parameter_value// /}\"
            if grep -Piq \"^\\h*$l_systemd_parameter_value\\b\" <<< \"$l_systemd_file_parameter_value\"; then
                l_output=\"$l_output\\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' \"${A_out[@]}\")\"\\n\"
            else
                l_output2=\"$l_output2\\n - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' \"${A_out[@]}\")\" and should have a value matching: \"$l_systemd_parameter_value\"\\n\"
            fi
          done < <(grep -Pio -- \"^\\h*$l_systemd_parameter_name\\h*=\\h*\\H+\" \"${A_out[@]}\")
      else
          l_output2=\"$l_output2\\n - \"$l_systemd_parameter_name\" is not set in an included file\\n   ** Note: \"$l_systemd_parameter_name\" May be set in a file that's ignored by load procedure **\\n\"
      fi
    }
    while IFS=\"=\" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
      l_systemd_parameter_name=\"${l_systemd_parameter_name// /}\"
      l_systemd_parameter_value=\"${l_systemd_parameter_value// /}\"
      config_file_parameter_chk
    done < <(printf '%s\\n' \"${a_parlist[@]}\")
    if [ -z \"$l_output2\" ]; then # Provide output from checks
      echo -e \"\\n- Audit Result:\\n  ** PASS **\\n$l_output\\n\"
    else
      echo -e \"\\n- Audit Result:\\n  ** FAIL **\n - Reason(s) for audit failure:\\n$l_output2\"
      [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"
    fi
  }").stdout
  describe systemd_timesyncd_configured_with_authorized_timeserver do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.3.2.2_Ensure_systemd-timesyncd_is_enabled_and_running' do
  title 'Ensure systemd-timesyncd is enabled and running'
  desc  "
    systemd-timesyncd is a daemon that has been added for synchronizing the system clock across the network

    Rationale: systemd-timesyncd needs to be enabled and running in order to synchronize the system to a timeserver.

    Time synchronization is important to support time sensitive security mechanisms and to ensure log files have consistent time records across the enterprise to aid in forensic investigations
  "
  impact 0.0
  describe.one do
    describe service('systemd-timesyncd') do
      it { should be_enabled }
      its('params.ActiveState') { should eq 'active' }
    end
    describe service('systemd-timesyncd') do
      its('params.UnitFileState') { should eq 'masked' }
      its('params.ActiveState') { should eq 'inactive' }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.3.3.1_Ensure_chrony_is_configured_with_authorized_timeserver' do
  title 'Ensure chrony is configured with authorized timeserver'
  desc  "
    * server

    * The server directive specifies an NTP server which can be used as a time source. The client-server relationship is strictly hierarchical: a client might synchronize its system time to that of the server, but the server&#x2019;s system time will never be influenced by that of a client.
    * This directive can be used multiple times to specify multiple servers.
    * The directive is immediately followed by either the name of the server, or its IP address.
    * pool

    * The syntax of this directive is similar to that for the server directive, except that it is used to specify a pool of NTP servers rather than a single NTP server. The pool name is expected to resolve to multiple addresses which might change over time.
    * This directive can be used multiple times to specify multiple pools.
    * All options valid in the server directive can be used in this directive too.

    Rationale: Time synchronization is important to support time sensitive security mechanisms and to ensure log files have consistent time records across the enterprise to aid in forensic investigations
  "
  impact 0.0
  describe.one do
    describe file('/etc/chrony/chrony.conf') do
      its('content') { should match(/^\s*(server|pool)\s+\S+/) }
    end
    files = command('find /etc/chrony/ -type f -regex .\\*/\\^.+\\\\.\\(conf\\|sources\\)').stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\h*(server|pool)\h+\H+/ } do
      it { should_not be_empty }
    end
    describe package('chrony') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.3.3.2_Ensure_chrony_is_running_as_user__chrony' do
  title 'Ensure chrony is running as user _chrony'
  desc  "
    The chrony package is installed with a dedicated user account _chrony .  This account is granted the access required by the chronyd service

    Rationale: The chronyd service should run with only the required privlidges
  "
  impact 1.0
  describe.one do
    describe command("ps -ef | awk \'(/[c]hronyd/ && $1!=\"_chrony\") { print $1 }\'").stdout do
      it { should be_empty }
    end
    describe package('chrony') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.3.3.3_Ensure_chrony_is_enabled_and_running' do
  title 'Ensure chrony is enabled and running'
  desc  "
    chrony is a daemon for synchronizing the system clock across the network

    Rationale: chrony needs to be enabled and running in order to synchronize the system to a timeserver.

    Time synchronization is important to support time sensitive security mechanisms and to ensure log files have consistent time records across the enterprise to aid in forensic investigations
  "
  impact 1.0
  if package('chrony').installed?
    describe service('chrony') do
      it { should be_enabled }
      its('params.ActiveState') { should eq 'active' }
    end
  else
    describe package('chrony') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.1_Ensure_cron_daemon_is_enabled_and_active' do
  title 'Ensure cron daemon is enabled and active'
  desc  "
    The cron daemon is used to execute batch jobs on the system.

    Rationale: While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and cron is used to execute them.
  "
  impact 1.0
  describe.one do
    describe service('cron') do
      it { should be_enabled }
      it { should be_running }
    end
    describe package('cron') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.2_Ensure_permissions_on_etccrontab_are_configured' do
  title 'Ensure permissions on /etc/crontab are configured'
  desc  "
    The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and that only the owner can access the file.

    Rationale: This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access.
  "
  impact 1.0
  if package('cron').installed? || package('cronie').installed?
    describe file('/etc/crontab') do
      it { should exist }
      it { should_not be_more_permissive_than('0600') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  else
    describe package('cron') do
      it { should_not be_installed }
    end
    describe package('cronie') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.3_Ensure_permissions_on_etccron.hourly_are_configured' do
  title 'Ensure permissions on /etc/cron.hourly are configured'
  desc  "
    This directory contains system cron jobs that need to run on an hourly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.

    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  if package('cron').installed? || package('cronie').installed?
    describe directory('/etc/cron.hourly/') do
      it { should exist }
      it { should_not be_more_permissive_than('0700') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  else
    describe package('cron') do
      it { should_not be_installed }
    end
    describe package('cronie') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.4_Ensure_permissions_on_etccron.daily_are_configured' do
  title 'Ensure permissions on /etc/cron.daily are configured'
  desc  "
    The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.

    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  if package('cron').installed? || package('cronie').installed?
    describe directory('/etc/cron.daily/') do
      it { should exist }
      it { should_not be_more_permissive_than('0700') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  else
    describe package('cron') do
      it { should_not be_installed }
    end
    describe package('cronie') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.5_Ensure_permissions_on_etccron.weekly_are_configured' do
  title 'Ensure permissions on /etc/cron.weekly are configured'
  desc  "
    The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.

    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  if package('cron').installed? || package('cronie').installed?
    describe directory('/etc/cron.weekly/') do
      it { should exist }
      it { should_not be_more_permissive_than('0700') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  else
    describe package('cron') do
      it { should_not be_installed }
    end
    describe package('cronie') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.6_Ensure_permissions_on_etccron.monthly_are_configured' do
  title 'Ensure permissions on /etc/cron.monthly are configured'
  desc  "
    The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.

    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  if package('cron').installed? || package('cronie').installed?
    describe directory('/etc/cron.monthly/') do
      it { should exist }
      it { should_not be_more_permissive_than('0700') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  else
    describe package('cron') do
      it { should_not be_installed }
    end
    describe package('cronie') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.7_Ensure_permissions_on_etccron.d_are_configured' do
  title 'Ensure permissions on /etc/cron.d are configured'
  desc  "
    The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly, daily weekly and monthly jobs from /etc/crontab , but require more granular control as to when they run. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.

    Rationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  impact 1.0
  if package('cron').installed? || package('cronie').installed?
    describe directory('/etc/cron.d/') do
      it { should exist }
      it { should_not be_more_permissive_than('0700') }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
    end
  else
    describe package('cron') do
      it { should_not be_installed }
    end
    describe package('cronie') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.1.8_Ensure_crontab_is_restricted_to_authorized_users' do
  title 'Ensure crontab is restricted to authorized users'
  desc  "
    crontab is the program used to install, deinstall, or list the tables used to drive the cron daemon. Each user can have their own crontab, and though these are files in /var/spool/cron/crontabs , they are not intended to be edited directly.

    If the /etc/cron.allow file exists, then you must be listed (one user per line) therein in order to be allowed to use this command. If the /etc/cron.allow file does not exist but the /etc/cron.deny file does exist, then you must not be listed in the /etc/cron.deny file in order to use this command.

    If neither of these files exists, then depending on site-dependent configuration parameters, only the super user will be allowed to use this command, or all users will be able to use this command.

    If both files exist then /etc/cron.allow takes precedence. Which means that /etc/cron.deny is not considered and your user must be listed in /etc/cron.allow in order to be able to use the crontab.

    Regardless of the existence of any of these files, the root administrative user is always allowed to setup a crontab.

    The files /etc/cron.allow and /etc/cron.deny , if they exist, must be either world-readable, or readable by group crontab . If they are not, then cron will deny access to all users until the permissions are fixed.

    There is one file for each user's crontab under the /var/spool/cron/crontabs directory. Users are not allowed to edit the files under that directory directly to ensure that only users allowed by the system to run periodic tasks can add them, and only syntactically correct crontabs will be written there. This is enforced by having the directory writable only by the crontab group and configuring crontab command with the setgid bid set for that specific group.

    **Note:**

    *  Even though a given user is not listed in cron.allow , cron jobs can still be run as that user
    *  The files /etc/cron.allow and /etc/cron.deny , if they exist, only controls administrative access to the crontab command for scheduling and modifying cron jobs

    Rationale: On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  impact 1.0
  if package('cron').installed? || package('cronie').installed?
    describe file('/etc/cron.allow') do
      it { should exist }
      it { should_not be_more_permissive_than('0640') }
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
    end
    if file('/etc/cron.deny').exist?
      describe file('/etc/cron.deny') do
        it { should exist }
        it { should_not be_more_permissive_than('0640') }
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
      end
    else
      describe file('/etc/cron.deny') do
        it { should_not exist }
      end
    end
  else
    describe package('cron') do
      it { should_not be_installed }
    end
    describe package('cronie') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_2.4.2.1_Ensure_at_is_restricted_to_authorized_users' do
  title 'Ensure at is restricted to authorized users'
  desc  "
    at allows fairly complex time specifications, extending the POSIX.2 standard. It accepts times of the form HH:MM to run a job at a specific time of day. (If that time is already past, the next day is assumed.) You may also specify midnight, noon, or teatime (4pm) and you can have a time-of-day suffixed with AM or PM for running in the morning or the evening. You can also say what day the job will be run, by giving a date in the form month-name day with an optional year, or giving a date of the form MMDD[CC]YY, MM/DD/[CC]YY,  DD.MM.[CC]YY or [CC]YY-MM-DD. The specification of a date must follow the specification of the time of day. You can also give times like now + count time-units, where the time-units can be minutes, hours, days, or weeks and you can tell at to run the job today by suffixing the time with today and to run the job tomorrow by suffixing the time with tomorrow.

    The /etc/at.allow and /etc/at.deny files determine which user can submit commands for later execution via at or batch. The format of the files is a list of usernames, one on each line. Whitespace is not permitted. If the file /etc/at.allow exists, only usernames mentioned in it are allowed to use at. If /etc/at.allow does not exist, /etc/at.deny is checked, every username not mentioned in it is then allowed to use at. An empty /etc/at.deny means that every user may use at. If neither file exists, only the superuser is allowed to use at.

    Rationale: On many systems, only the system administrator is authorized to schedule at jobs. Using the at.allow file to control who can run at jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files.
  "
  impact 1.0
  if package('at').installed?
    describe file('/etc/at.allow') do
      it { should exist }
      it { should_not be_more_permissive_than('0640') }
      its('owner') { should cmp 'root' }
      its('group') { should be_in %w(daemon root) }
    end
    if file('/etc/at.deny').exist?
      describe file('/etc/at.deny') do
        it { should_not be_more_permissive_than('0640') }
        its('owner') { should cmp 'root' }
        its('group') { should be_in %w(daemon root) }
      end
    else
      describe file('/etc/at.deny') do
        it { should_not exist }
      end
    end
  else
    describe package('at') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.1.1_Ensure_IPv6_status_is_identified' do
  title 'Ensure IPv6 status is identified'
  desc  "
    Internet Protocol Version 6 (IPv6) is the most recent version of Internet Protocol (IP). It's designed to supply IP addressing and additional security to support the predicted growth of connected devices. IPv6 is based on 128-bit addressing and can support 340 undecillion, which is 340 trillion3 addresses.

    Features of IPv6

    * Hierarchical addressing and routing infrastructure
    * Stateful and Stateless configuration
    * Support for quality of service (QoS)
    * An ideal protocol for neighboring node interaction

    Rationale: IETF RFC 4038 recommends that applications are built with an assumption of dual stack. It is recommended that IPv6 be enabled and configured in accordance with Benchmark recommendations.

    **-IF-** dual stack and IPv6 are not used in your environment, IPv6 may be disabled to reduce the attack surface of the system, and recommendations pertaining to IPv6 can be skipped.

    **Note:** It is recommended that IPv6 be enabled and configured unless this is against local site policy
  "
  impact 0.0
  output = bash("grep -Pqs '^\\s*0\\b' /sys/module/ipv6/parameters/disable && echo -e \"\n - IPv6 is enabled\n\" || echo -e \"\n - IPv6 is not enabled\n\"").stdout
  if ipv6_status.casecmp('enabled') == 0
    describe output do
      it { should match('IPv6 is enabled') }
    end
  elsif ipv6_status.casecmp('disabled') == 0
    describe output do
      it { should match('IPv6 is not enabled') }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.1.2_Ensure_wireless_interfaces_are_disabled' do
  title 'Ensure wireless interfaces are disabled'
  desc  "
    Wireless networking is used when wired networks are unavailable.

    Rationale: **-IF-** wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface.
  "
  impact 1.0
  describe bash("l_output=\"\" l_output2=\"\"\nmodule_chk()\n{\n   # Check how module will be loaded\n   l_loadable=\"$(modprobe -n -v \"$l_mname\")\"\n   if grep -Pq -- '^\\h*install \\/bin\\/(true|false)' <<< \"$l_loadable\"; then\n      l_output=\"$l_output\\n - module: \\\"$l_mname\\\" is not loadable: \\\"$l_loadable\\\"\"\n   else\n      l_output2=\"$l_output2\\n - module: \\\"$l_mname\\\" is loadable: \\\"$l_loadable\\\"\"\n   fi\n   # Check is the module currently loaded\n   if ! lsmod | grep \"$l_mname\" > /dev/null 2>&1; then\n      l_output=\"$l_output\\n - module: \\\"$l_mname\\\" is not loaded\"\n   else\n      l_output2=\"$l_output2\\n - module: \\\"$l_mname\\\" is loaded\"\n   fi\n   # Check if the module is deny listed\n   if modprobe --showconfig | grep -Pq -- \"^\\h*blacklist\\h+$l_mname\\b\"; then\n      l_output=\"$l_output\\n - module: \\\"$l_mname\\\" is deny listed in: \\\"$(grep -Pl -- \"^\\h*blacklist\\h+$l_mname\\b\" /etc/modprobe.d/*)\\\"\"\n   else\n      l_output2=\"$l_output2\\n - module: \\\"$l_mname\\\" is not deny listed\"\n   fi\n}\nif [ -n \"$(find /sys/class/net/*/ -type d -name wireless)\" ]; then\n   l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename \"$(readlink -f \"$driverdir\"/device/driver/module)\";done | sort -u)\n   for l_mname in $l_dname; do\n      module_chk\n   done\nfi\n# Report results. If no failures output in l_output2, we pass\nif [ -z \"$l_output2\" ]; then\n   echo -e \"\\n- Audit Result:\\n  ** PASS **\"\n   if [ -z \"$l_output\" ]; then\n      echo -e \"\\n - System has no wireless NICs installed\"\n   else\n      echo -e \"\\n$l_output\\n\"\n   fi\n   exit 0\nelse\n   echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - Reason(s) for audit failure:\\n$l_output2\\n\"\n   [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"\n   exit 1\nfi").stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.1.3_Ensure_bluetooth_services_are_not_in_use' do
  title 'Ensure bluetooth services are not in use'
  desc  "
    Bluetooth is a short-range wireless technology standard that is used for exchanging data between devices over short distances. It employs UHF radio waves in the ISM bands, from 2.402 GHz to 2.48 GHz. It is mainly used as an alternative to wire connections.

    Rationale: An attacker may be able to find a way to access or corrupt your data. One example of this type of activity is bluesnarfing , which refers to attackers using a Bluetooth connection to steal information off of your Bluetooth device. Also, viruses or other malicious code can take advantage of Bluetooth technology to infect other devices. If you are infected, your data may be corrupted, compromised, stolen, or lost.
  "
  impact 1.0
  if package('bluez').installed?
    describe service('bluetooth') do
      it { should_not be_enabled }
      its('params.ActiveState') { should_not eq 'active' }
    end
  else
    describe package('bluez') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.1_Ensure_ip_forwarding_is_disabled' do
  title 'Ensure ip forwarding is disabled'
  desc  "
    The net.ipv4.ip_forward and net.ipv6.conf.all.forwarding flags are used to tell the system whether it can forward packets or not.

    Rationale: Setting net.ipv4.ip_forward and net.ipv6.conf.all.forwarding to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router.
  "
  impact 1.0
  ipv6_disabled = kernel_parameter('net.ipv6.conf.all.disable_ipv6').value == 1 && kernel_parameter('net.ipv6.conf.default.disable_ipv6').value == 1
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.ip_forward\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.ip_forward\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  if ipv6_disabled
    describe 'IPv6 is disabled' do
      skip 'IPv6 is disabled, so this parameter is not applicable.'
    end
  else
    describe kernel_parameter('net.ipv6.conf.all.forwarding') do
      its('value') { should eq 0 }
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.forwarding\s*=\s*0\s*$/ } do
      it 'Files configured with correct Kernel Parameter' do
        expect(subject).not_to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.forwarding\s*=\s*[1-9]\d*\s*$/ } do
      it 'Files configured with incorrect Kernel Parameter' do
        expect(subject).to be_empty
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.2_Ensure_packet_redirect_sending_is_disabled' do
  title 'Ensure packet redirect sending is disabled'
  desc  "
    ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects.

    Rationale: An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system.
  "
  impact 1.0
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should eq 0 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.send_redirects\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.send_redirects\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.send_redirects\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.send_redirects\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.3_Ensure_bogus_icmp_responses_are_ignored' do
  title 'Ensure bogus icmp responses are ignored'
  desc  "
    Setting net.ipv4.icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages.

    Rationale: Some routers (and some attackers) will send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages.
  "
  impact 1.0
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should eq 1 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*1\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*(?!1\b)\d+\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.4_Ensure_broadcast_icmp_requests_are_ignored' do
  title 'Ensure broadcast icmp requests are ignored'
  desc  "
    Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.

    Rationale: Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied.
  "
  impact 1.0
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*(?!1\b)\d+\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.5_Ensure_icmp_redirects_are_not_accepted' do
  title 'Ensure icmp redirects are not accepted'
  desc  "
    ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables.

    Rationale: ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects , net.ipv4.conf.default.accept_redirects , net.ipv6.conf.all.accept_redirects , and net.ipv6.conf.default.accept_redirects to 0 , the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update the system's routing tables.
  "
  impact 1.0
  ipv6_disabled = kernel_parameter('net.ipv6.conf.all.disable_ipv6').value == 1 && kernel_parameter('net.ipv6.conf.default.disable_ipv6').value == 1
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.accept_redirects\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.accept_redirects\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.accept_redirects\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.accept_redirects\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  if ipv6_disabled
    describe 'IPv6 is disabled' do
      skip 'IPv6 is disabled, so this parameter is not applicable.'
    end
  else
    describe kernel_parameter('net.ipv6.conf.all.accept_redirects') do
      its('value') { should eq 0 }
    end
    describe kernel_parameter('net.ipv6.conf.default.accept_redirects') do
      its('value') { should eq 0 }
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_redirects\s*=\s*0\s*$/ } do
      it 'Files configured with correct Kernel Parameter' do
        expect(subject).not_to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_redirects\s*=\s*[1-9]\d*\s*$/ } do
      it 'Files configured with incorrect Kernel Parameter' do
        expect(subject).to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_redirects\s*=\s*0\s*$/ } do
      it 'Files configured with correct Kernel Parameter' do
        expect(subject).not_to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_redirects\s*=\s*[1-9]\d*\s*$/ } do
      it 'Files configured with incorrect Kernel Parameter' do
        expect(subject).to be_empty
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.6_Ensure_secure_icmp_redirects_are_not_accepted' do
  title 'Ensure secure icmp redirects are not accepted'
  desc  "
    Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed on the default gateway list. It is assumed that these gateways are known to your system, and that they are likely to be secure.

    Rationale: It is still possible for even known gateways to be compromised. Setting net.ipv4.conf.all.secure_redirects and net.ipv4.conf.default.secure_redirects to 0 protects the system from routing table updates by possibly compromised known gateways.
  "
  impact 1.0
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.secure_redirects') do
    its('value') { should eq 0 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.secure_redirects\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.secure_redirects\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.secure_redirects\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.secure_redirects\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.7_Ensure_reverse_path_filtering_is_enabled' do
  title 'Ensure reverse path filtering is enabled'
  desc  "
    Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces the Linux kernel to utilize reverse path filtering on a received packet to determine if the packet was valid. Essentially, with reverse path filtering, if the return packet does not go out the same interface that the corresponding source packet came from, the packet is dropped (and logged if log_martians is set).

    Rationale: Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 is a good way to deter attackers from sending your system bogus packets that cannot be responded to. One instance where this feature breaks down is if asymmetrical routing is employed. This would occur when using dynamic routing protocols (bgp, ospf, etc) on your system. If you are using asymmetrical routing on your system, you will not be able to enable this feature without breaking the routing.
  "
  impact 1.0
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should eq 1 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.rp_filter\s*=\s*1\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.rp_filter\s*=\s*(?!1\b)\d+\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.rp_filter\s*=\s*1\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.rp_filter\s*=\s*(?!1\b)\d+\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.8_Ensure_source_routed_packets_are_not_accepted' do
  title 'Ensure source routed packets are not accepted'
  desc  "
    In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.

    Rationale: Setting net.ipv4.conf.all.accept_source_route , net.ipv4.conf.default.accept_source_route , net.ipv6.conf.all.accept_source_route and net.ipv6.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this system was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the system as a way to reach the private address systems. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing.
  "
  impact 1.0
  ipv6_disabled = kernel_parameter('net.ipv6.conf.all.disable_ipv6').value == 1 && kernel_parameter('net.ipv6.conf.default.disable_ipv6').value == 1
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.accept_source_route\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.accept_source_route\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.accept_source_route\s*=\s*0\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.accept_source_route\s*=\s*[1-9]\d*\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  if ipv6_disabled
    describe 'IPv6 is disabled' do
      skip 'IPv6 is disabled, so this parameter is not applicable.'
    end
  else
    describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
      its('value') { should eq 0 }
    end
    describe kernel_parameter('net.ipv6.conf.default.accept_source_route') do
      its('value') { should eq 0 }
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_source_route\s*=\s*0\s*$/ } do
      it 'Files configured with correct Kernel Parameter' do
        expect(subject).not_to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_source_route\s*=\s*[1-9]\d*\s*$/ } do
      it 'Files configured with incorrect Kernel Parameter' do
        expect(subject).to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_source_route\s*=\s*0\s*$/ } do
      it 'Files configured with correct Kernel Parameter' do
        expect(subject).not_to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_source_route\s*=\s*[1-9]\d*\s*$/ } do
      it 'Files configured with incorrect Kernel Parameter' do
        expect(subject).to be_empty
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.9_Ensure_suspicious_packets_are_logged' do
  title 'Ensure suspicious packets are logged'
  desc  "
    When enabled, this feature logs packets with un-routable source addresses to the kernel log.

    Rationale: Setting net.ipv4.conf.all.log_martians and net.ipv4.conf.default.log_martians to 1 enables this feature. Logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their system.
  "
  impact 1.0
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should eq 1 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.log_martians\s*=\s*1\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.all.log_martians\s*=\s*(?!1\b)\d+\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.log_martians\s*=\s*1\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.conf.default.log_martians\s*=\s*(?!1\b)\d+\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.10_Ensure_tcp_syn_cookies_is_enabled' do
  title 'Ensure tcp syn cookies is enabled'
  desc  "
    When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the system to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue.

    Rationale: Attackers use SYN flood attacks to perform a denial of service attacked on a system by sending many SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. Setting net.ipv4.tcp_syncookies to 1 enables SYN cookies, allowing the system to keep accepting valid connections, even if under a denial of service attack.
  "
  impact 1.0
  files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
  unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
    files += ['/etc/default/ufw']
  end
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.tcp_syncookies\s*=\s*1\s*$/ } do
    it 'Files configured with correct Kernel Parameter' do
      expect(subject).not_to be_empty
    end
  end
  describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv4.tcp_syncookies\s*=\s*(?!1\b)\d+\s*$/ } do
    it 'Files configured with incorrect Kernel Parameter' do
      expect(subject).to be_empty
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_3.3.11_Ensure_ipv6_router_advertisements_are_not_accepted' do
  title 'Ensure ipv6 router advertisements are not accepted'
  desc  "
    This setting disables the system's ability to accept IPv6 router advertisements.

    Rationale: It is recommended that systems do not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes. Setting net.ipv6.conf.all.accept_ra and net.ipv6.conf.default.accept_ra to 0 disables the system's ability to accept IPv6 router advertisements.
  "
  impact 1.0
  ipv6_disabled = kernel_parameter('net.ipv6.conf.all.disable_ipv6').value == 1 && kernel_parameter('net.ipv6.conf.default.disable_ipv6').value == 1
  if ipv6_disabled
    describe 'IPv6 is disabled' do
      skip 'IPv6 is disabled, so this parameter is not applicable.'
    end
  else
    files = command("/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '#\\s*\/([^#\\n\\r\s]+\\.conf)\\b' | awk '{print $2}' ").stdout.split
    unless bash("[ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw").stdout.strip.empty?
      files += ['/etc/default/ufw']
    end
    describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
      its('value') { should eq 0 }
    end
    describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
      its('value') { should eq 0 }
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_ra\s*=\s*0\s*$/ } do
      it 'Files configured with correct Kernel Parameter' do
        expect(subject).not_to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.all.accept_ra\s*=\s*[1-9]\d*\s*$/ } do
      it 'Files configured with incorrect Kernel Parameter' do
        expect(subject).to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_ra\s*=\s*0\s*$/ } do
      it 'Files configured with correct Kernel Parameter' do
        expect(subject).not_to be_empty
      end
    end
    describe files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*net.ipv6.conf.default.accept_ra\s*=\s*[1-9]\d*\s*$/ } do
      it 'Files configured with incorrect Kernel Parameter' do
        expect(subject).to be_empty
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.1.1_Ensure_ufw_is_installed' do
  title 'Ensure ufw is installed'
  desc  "
    The Uncomplicated Firewall (ufw) is a frontend for iptables and is particularly well-suited for host-based firewalls. ufw provides a framework for managing netfilter, as well as a command-line interface for manipulating the firewall

    Rationale: A firewall utility is required to configure the Linux kernel's netfilter framework via the iptables or nftables back-end.

    The Linux kernel's netfilter framework host-based firewall can protect against threats originating from within a corporate network to include malicious mobile code and poorly configured software on a host.

    **Note:** Only one firewall utility should be installed and configured. UFW is dependent on the iptables package
  "
  impact 1.0
  only_if('This recommendation applies only to environments using ufw as firewall utility.') { firewall_utility == 'ufw' }
  describe package('ufw') do
    it { should be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.1.2_Ensure_iptables-persistent_is_not_installed_with_ufw' do
  title 'Ensure iptables-persistent is not installed with ufw'
  desc  "
    The iptables-persistent is a boot-time loader for netfilter rules, iptables plugin

    Rationale: Running both ufw and the services included in the iptables-persistent package may lead to conflict
  "
  impact 1.0
  only_if('This recommendation applies only to environments using ufw as firewall utility.') { firewall_utility == 'ufw' }
  describe package('iptables-persistent') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.1.3_Ensure_ufw_service_is_enabled' do
  title 'Ensure ufw service is enabled'
  desc  "
    UncomplicatedFirewall (ufw) is a frontend for iptables. ufw provides a framework for managing netfilter, as well as a command-line and available graphical user interface for manipulating the firewall.

    **Note:**

    * When running ufw enable or starting ufw via its initscript, ufw will flush its chains. This is required so ufw can maintain a consistent state, but it may drop existing connections (eg ssh).  ufw does support adding rules before enabling the firewall.
    *  Run the following command before running ufw enable .
    # ufw allow proto tcp from any to any port 22 * The rules will still be flushed, but the ssh port will be open after enabling the firewall. Please note that once ufw is 'enabled', ufw will not flush the chains when adding or removing rules (but will when modifying a rule or changing the default policy)
    *  By default, ufw will prompt when enabling the firewall while running under ssh. This can be disabled by using ufw --force enable

    Rationale: The ufw service must be enabled and running in order for ufw to protect the system
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using ufw as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'ufw' }
  describe service('ufw') do
    it { should be_enabled }
    it { should be_running }
  end
  describe command('ufw status') do
    its('stdout') { should match(/^\s*Status:\s*active/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.1.4_Ensure_ufw_loopback_traffic_is_configured' do
  title 'Ensure ufw loopback traffic is configured'
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (127.0.0.0/8 for IPv4 and ::1/128 for IPv6).

    Rationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (127.0.0.0/8 for IPv4 and ::1/128 for IPv6) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using UFW') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'ufw' }
  describe command('ufw status verbose') do
    its('stdout') { should match(%r{^\s*Anywhere\s+DENY\s+IN\s+127\.0\.0\.0/8\b}) }
    its('stdout') { should match(/^\s*Anywhere\s+on\s+lo\s+ALLOW\s+IN\s+Anywhere\b/) }
    its('stdout') { should match(/^\s*Anywhere\s+ALLOW\s+OUT\s+Anywhere\s+on\s+lo\b/) }
  end
  if command("grep -E '^\s*0\s*$' /sys/module/ipv6/parameters/disable").stdout.strip != ''
    describe command('ufw status verbose') do
      its('stdout') { should match(/^\s*Anywhere\s+\(v6\)\s+DENY\s+IN\s+\:\:1\b/) }
      its('stdout') { should match(/^\s*Anywhere\s+\(v6\)\s+on\s+lo\s+ALLOW\s+IN\s+Anywhere\s+\(v6\)\s*\b/) }
      its('stdout') { should match(/^\s*Anywhere\s+\(v6\)\s+ALLOW\s+OUT\s+Anywhere\s+\(v6\)\s+on\s+lo\b/) }
    end
  else
    describe 'IPv6' do
      it 'IPv6 disabled on system.' do
        expect(command("grep -E '^\s*0\s*$' /sys/module/ipv6/parameters/disable").stdout).to be_empty
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.1.5_Ensure_ufw_outbound_connections_are_configured' do
  title 'Ensure ufw outbound connections are configured'
  desc  "
    Configure the firewall rules for new outbound connections.

    **Note:**

    * Changing firewall settings while connected over network can result in being locked out of the system.
    * Unlike iptables, when a new outbound rule is added, ufw automatically takes care of associated established connections, so no rules for the latter kind are required.

    Rationale: If rules are not in place for new outbound connections all packets will be dropped by the default policy preventing network usage.
  "
  impact 0.0
  describe 'This recommendation cannot be checked automatically' do
    skip('This recommendation requires manual review -
      Run the following command and verify all rules for new outbound connections match site policy:
      # ufw status numbered')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.1.6_Ensure_ufw_firewall_rules_exist_for_all_open_ports' do
  title 'Ensure ufw firewall rules exist for all open ports'
  desc  "
    Services and ports can be accepted or explicitly rejected.

    **Note:**

    * Changing firewall settings while connected over network can result in being locked out of the system
    * The remediation command opens up the port to traffic from all sources. Consult ufw documentation and set any restrictions in compliance with site policy

    Rationale: To reduce the attack surface of a system, all services and ports should be blocked unless required.

    * Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
    * Without a firewall rule configured for open ports, the default firewall policy will drop all packets to these ports.
    * Required ports should have a firewall rule created to allow approved connections in accordance with local site policy.
    * Unapproved ports should have an explicit deny rule created.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using ufw as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'ufw' }
  describe bash('
  {
    unset a_ufwout;unset a_openports
    while read -r l_ufwport; do
      [ -n "$l_ufwport" ] && a_ufwout+=("$l_ufwport")
    done < <(ufw status verbose | grep -Po \'^\h*\d+\b\' | sort -u)
    while read -r l_openport; do
      [ -n "$l_openport" ] && a_openports+=("$l_openport")
    done < <(ss -tuln | awk \'($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/\[?::1\]?:/) {split($5, a, ":"); print a[2]}\' | sort -u)
    a_diff=("$(printf \'%s\n\' "${a_openports[@]}" "${a_ufwout[@]}" "${a_ufwout[@]}" | sort | uniq -u)")
    if [[ -n "${a_diff[*]}" ]]; then
      echo -e "\n- Audit Result:\n  ** FAIL **\n- The following port(s) don\'t have a rule in UFW: $(printf \'%s\n\' \\n"${a_diff[*]}")\n- End List"
    else
      echo -e "\n - Audit Passed -\n- All open ports have a rule in UFW\n"
    fi
  }') do
    its('stdout') { should match(/Audit\s+Passed/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.1.7_Ensure_ufw_default_deny_firewall_policy' do
  title 'Ensure ufw default deny firewall policy'
  desc  "
    A default deny policy on connections ensures that any unconfigured network usage will be rejected.

    **Note:** Any port or protocol without a explicit allow before the default deny will be blocked

    Rationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using UFW') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'ufw' }
  describe command('ufw status verbose | grep Default:') do
    its('stdout') { should match(/^\s*Default:\s+(deny|reject)\s+\(incoming\),\s*\S+\s+\(outgoing\),\s*\S+\s+\(routed\)/) }
    its('stdout') { should match(/^\s*Default:\s+\S+\s+\(incoming\),\s*(deny|reject)\s+\(outgoing\),\s*\S+\s+\(routed\)/) }
    its('stdout') { should match(/^\s*Default:\s+\S+\s+\(incoming\),\s*\S+\s+\(outgoing\),\s*(disabled|deny|reject)\s+\(routed\)/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.1_Ensure_nftables_is_installed' do
  title 'Ensure nftables is installed'
  desc  "
    nftables provides a new in-kernel packet classification framework that is based on a network-specific Virtual Machine (VM) and a new nft userspace command line tool. nftables reuses the existing Netfilter subsystems such as the existing hook infrastructure, the connection tracking system, NAT, userspace queuing and logging subsystem.

    **Notes:**

    * nftables is available in Linux kernel 3.13 and newer
    * Only one firewall utility should be installed and configured
    * Changing firewall settings while connected over the network can result in being locked out of the system

    Rationale: nftables is a subsystem of the Linux kernel that can protect against threats originating from within a corporate network to include malicious mobile code and poorly configured software on a host.
  "
  impact 1.0
  only_if('This recommendation applies only to environments using nftables as firewall utility.') { firewall_utility == 'nftables' }
  describe package('nftables') do
    it { should be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.2_Ensure_ufw_is_uninstalled_or_disabled_with_nftables' do
  title 'Ensure ufw is uninstalled or disabled with nftables'
  desc  "
    Uncomplicated Firewall (UFW) is a program for managing a netfilter firewall designed to be easy to use.

    Rationale: Running both the nftables service and ufw may lead to conflict and unexpected results.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using nftables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'nftables' }
  if package('ufw').installed?
    describe service('ufw') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe command('ufw status') do
      its('stdout') { should match(/^\s*Status:\s*inactive\b/) }
    end
  else
    describe package('ufw') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.3_Ensure_iptables_are_flushed_with_nftables' do
  title 'Ensure iptables are flushed with nftables'
  desc  "
    nftables is a replacement for iptables, ip6tables, ebtables and arptables

    Rationale: It is possible to mix iptables and nftables. However, this increases complexity and also the chance to introduce errors. For simplicity flush out all iptables rules, and ensure it is not loaded
  "
  impact 0.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'nftables' }
  describe command('iptables -L --line-numbers') do
    its('stdout') { should_not match(/^\s*\d/) }
  end
  describe command('ip6tables -L --line-numbers') do
    its('stdout') { should_not match(/^\s*\d/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.4_Ensure_a_nftables_table_exists' do
  title 'Ensure a nftables table exists'
  desc  "
    Tables hold chains.  Each table only has one address family and only applies to packets of this family.  Tables can have one of five families.

    Rationale: nftables doesn't have any default tables.  Without a table being build, nftables will not filter network traffic.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'nftables' }
  describe command('nft list tables') do
    its('stdout') { should match(/^table\s+\S+\s+\S+/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.5_Ensure_nftables_base_chains_exist' do
  title 'Ensure nftables base chains exist'
  desc  "
    Chains are containers for rules. They exist in two kinds, base chains and regular chains. A base chain is an  entry  point  for packets from the networking stack, a regular chain may be used as jump target and is used for better rule organization.

    Rationale: If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through those chains will not be touched by nftables.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'nftables' }
  ruleset_options = %w(input forward output)
  ruleset_options.each do |option|
    describe command("nft list ruleset | grep 'hook #{option}'") do
      its('stdout') { should match(/^\s*\S+\s+\S+\s+hook\s+#{option}\b(\s+.*)?$/) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.6_Ensure_nftables_loopback_traffic_is_configured' do
  title 'Ensure nftables loopback traffic is configured'
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network

    Rationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'nftables' }
  describe command("nft list ruleset | awk '/hook input/,/}/' | grep 'iif \"lo\" accept'") do
    its('stdout') { should match(/^\s*iif\s+"lo"\s+accept/) }
  end
  describe command("nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'") do
    its('stdout') { should match(%r{^\s*ip\s+saddr\s+127\.0\.0\.0/8\s+counter\s+packets\s+0\s+bytes\s+0\s+drop}) }
  end
  if ipv6_status_system.match?(/IPv6 is enabled/) == true
    describe command("nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'") do
      its('stdout') { should match(/^\s*ip6\s+saddr\s+\:\:1\s+counter\s+packets\s+0\s+bytes\s+0\s+drop/) }
    end
  else
    describe ipv6_status_system do
      it { should match(/ipv6 disabled/i) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.7_Ensure_nftables_outbound_and_established_connections_are_configured' do
  title 'Ensure nftables outbound and established connections are configured'
  desc  "
    Configure the firewall rules for new outbound, and established connections

    Rationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage.
  "
  impact 0.0
  only_if('This recommendation applies only to environments using nftables as firewall utility.') { firewall_utility == 'nftables' }
  describe 'This recommendation cannot be checked automatically' do
    skip("Run the following commands and verify all rules for established incoming connections match site policy: site policy:
      # nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
      Output should be similar to:
      ip protocol tcp ct state established accept
      ip protocol udp ct state established accept
      ip protocol icmp ct state established accept
      Run the following command and verify all rules for new and established outbound connections match site policy
      # nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
      Output should be similar to:
      ip protocol tcp ct state established,related,new accept
      ip protocol udp ct state established,related,new accept
      ip protocol icmp ct state established,related,new accept")
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.8_Ensure_nftables_default_deny_firewall_policy' do
  title 'Ensure nftables default deny firewall policy'
  desc  "
    Base chain policy is the default verdict that will be applied to packets reaching the end of the chain.

    Rationale: There are two policies: accept (Default) and drop.  If the policy is set to accept , the firewall will accept any packet that is not configured to be denied and the packet will continue transversing the network stack.

    It is easier to white list acceptable usage than to black list unacceptable usage.

    **Note: Changing firewall settings while connected over network can result in being locked out of the system.**
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'nftables' }
  describe command("nft list ruleset | grep 'hook input'") do
    its('stdout') { should match(/^.*policy\s*drop;$/) }
  end
  describe command("nft list ruleset | grep 'hook forward'") do
    its('stdout') { should match(/^.*policy\s*drop;$/) }
  end
  describe command("nft list ruleset | grep 'hook output'") do
    its('stdout') { should match(/^.*policy\s*drop;$/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.9_Ensure_nftables_service_is_enabled' do
  title 'Ensure nftables service is enabled'
  desc  "
    The nftables service allows for the loading of nftables rulesets during boot, or starting on the nftables service

    Rationale: The nftables service restores the nftables rules from the rules files referenced in the /etc/nftables.conf file during boot or the starting of the nftables service
  "
  impact 1.0
  only_if('This recommendation applies only to environments using nftables as firewall utility.') { firewall_utility == 'nftables' }
  describe service('nftables') do
    it { should be_enabled }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.2.10_Ensure_nftables_rules_are_permanent' do
  title 'Ensure nftables rules are permanent'
  desc  "
    nftables is a subsystem of the Linux kernel providing filtering and classification of network packets/datagrams/frames.

    The nftables service reads the /etc/nftables.conf file for a nftables file or files to include in the nftables ruleset.

    A nftables ruleset containing the input, forward, and output base chains allow network traffic to be filtered.

    Rationale: Changes made to nftables ruleset only affect the live system, you will also need to configure the nftables ruleset to apply on boot
  "
  impact 1.0
  only_if('This recommendation applies only to environments using nftables as firewall utility.') { firewall_utility == 'nftables' }
  describe file('/etc/sysconfig/nftables.conf') do
    its('content') { should match(/^\s*include\s+'?\S+"?(\s+.*)?$/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.1.1_Ensure_iptables_packages_are_installed' do
  title 'Ensure iptables packages are installed'
  desc  "
    iptables is a utility program that allows a system administrator to configure the tables provided by the Linux kernel firewall, implemented as different Netfilter modules, and the chains and rules it stores. Different kernel modules and programs are used for different protocols; iptables applies to IPv4, ip6tables to IPv6, arptables to ARP, and ebtables to Ethernet frames.

    Rationale: A method of configuring and maintaining firewall rules is necessary to configure a Host Based Firewall.
  "
  impact 1.0
  only_if('This recommendation applies only to environments using iptables as firewall utility.') { firewall_utility == 'iptables' }
  describe package('iptables') do
    it { should be_installed }
  end
  describe package('iptables-persistent') do
    it { should be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.1.2_Ensure_nftables_is_not_installed_with_iptables' do
  title 'Ensure nftables is not installed with iptables'
  desc  "
    nftables is a subsystem of the Linux kernel providing filtering and classification of network packets/datagrams/frames and is the successor to iptables.

    Rationale: Running both iptables and nftables may lead to conflict.
  "
  impact 1.0
  only_if('This recommendation applies only to environments using iptables as firewall utility.') { firewall_utility == 'iptables' }
  describe package('nftables') do
    it { should_not be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.1.3_Ensure_ufw_is_uninstalled_or_disabled_with_iptables' do
  title 'Ensure ufw is uninstalled or disabled with iptables'
  desc  "
    Uncomplicated Firewall (UFW) is a program for managing a netfilter firewall designed to be easy to use.

    * Uses a command-line interface consisting of a small number of simple commands
    * Uses iptables for configuration

    Rationale: Running iptables.persistent with ufw enabled may lead to conflict and unexpected results.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  if package('ufw').installed?
    describe service('ufw') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe command('ufw status') do
      its('stdout') { should match(/^\s*Status:\s*inactive/) }
    end
  else
    describe package('ufw') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.2.1_Ensure_iptables_default_deny_firewall_policy' do
  title 'Ensure iptables default deny firewall policy'
  desc  "
    A default deny all policy on connections ensures that any unconfigured network usage will be rejected.

    **Notes:**

    * **Changing firewall settings while connected over network can result in being locked out of the system**
    * **Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well**

    Rationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  %w(INPUT OUTPUT FORWARD).each do |chain|
    describe.one do
      describe iptables do
        it { should have_rule("-P #{chain} DROP") }
      end
      describe iptables do
        it { should have_rule("-P #{chain} REJECT") }
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.2.2_Ensure_iptables_loopback_traffic_is_configured' do
  title 'Ensure iptables loopback traffic is configured'
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (127.0.0.0/8).

    **Notes:**

    * **Changing firewall settings while connected over network can result in being locked out of the system**
    * **Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well**

    Rationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  describe iptables do
    it { should have_rule('-A INPUT -i lo -j ACCEPT') }
    it { should have_rule('-A OUTPUT -o lo -j ACCEPT') }
    it { should have_rule('-A INPUT -s 127.0.0.0/8 -j DROP') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.2.3_Ensure_iptables_outbound_and_established_connections_are_configured' do
  title 'Ensure iptables outbound and established connections are configured'
  desc  "
    Configure the firewall rules for new outbound, and established connections.

    **Notes:**

    * **Changing firewall settings while connected over network can result in being locked out of the system**
    * **Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well**

    Rationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage.
  "
  impact 0.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  iptables_established_connections[0].each do |rule|
    current_connections = command("iptables -S #{rule}").stdout.strip
    iptables_established_connections[1].each do |connections|
      describe current_connections do
        it { should match connections }
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.2.4_Ensure_iptables_firewall_rules_exist_for_all_open_ports' do
  title 'Ensure iptables firewall rules exist for all open ports'
  desc  "
    Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.

    **Note:**

    * Changing firewall settings while connected over network can result in being locked out of the system
    * Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well
    * The remediation command opens up the port to traffic from all sources. Consult iptables documentation and set any restrictions in compliance with site policy

    Rationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  port.where { protocol =~ /.*/ && port >= 0 && address =~ /^(?!127\.0\.0\.1|::1|::).*$/ }.entries.each do |entry|
    rule_inbound = "-A INPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --dport #{entry[:port]} -m state --state NEW -j ACCEPT"
    describe iptables do
      it { should have_rule(rule_inbound) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.3.1_Ensure_ip6tables_default_deny_firewall_policy' do
  title 'Ensure ip6tables default deny firewall policy'
  desc  "
    A default deny all policy on connections ensures that any unconfigured network usage will be rejected.

    **Note:**

    * Changing firewall settings while connected over network can result in being locked out of the system
    * Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well

    Rationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  if ipv6_status_system.match?(/IPv6 is enabled/) == true
    %w(INPUT OUTPUT FORWARD).each do |chain|
      describe.one do
        describe ip6tables do
          it { should have_rule("-P #{chain} DROP") }
        end
        describe ip6tables do
          it { should have_rule("-P #{chain} REJECT") }
        end
      end
    end
  else
    describe 'Verify IPV6 status: IPV6 is not enabled on the system' do
      it { expect(ipv6_status_system).to match(/ipv6 disabled/i) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.3.2_Ensure_ip6tables_loopback_traffic_is_configured' do
  title 'Ensure ip6tables loopback traffic is configured'
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (::1).

    **Note:**

    * Changing firewall settings while connected over network can result in being locked out of the system
    * Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well

    Rationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (::1) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  if ipv6_status_system.match?(/IPv6 is enabled/) == true
    describe ip6tables do
      it { should have_rule('-A INPUT -i lo -j ACCEPT') }
      it { should have_rule('-A OUTPUT -o lo -j ACCEPT') }
    end
    ipv6_rules = command('ip6tables -L INPUT -v -n').stdout.strip.split("\n")
    describe "Ip6tables should have rule '-A INPUT -s ::1 -j DROP'" do
      it { expect(ipv6_rules.any? { |rule| rule.match?(/DROP.*::1/) }).to eq true }
    end
  else
    describe 'Verify IPV6 status: IPV6 is not enabled on the system' do
      it { expect(ipv6_status_system).to match(/ipv6 disabled/i) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.3.3_Ensure_ip6tables_outbound_and_established_connections_are_configured' do
  title 'Ensure ip6tables outbound and established connections are configured'
  desc  "
    Configure the firewall rules for new outbound, and established IPv6 connections.

    **Note:**

    * Changing firewall settings while connected over network can result in being locked out of the system
    * Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well

    Rationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage.
  "
  impact 0.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  if ipv6_status_system.match?(/IPv6 is enabled/) == true
    ip6tables_established_connections[0].each do |rule|
      current_connections = command("ip6tables -S #{rule}").stdout.strip
      ip6tables_established_connections[1].each do |connections|
        describe current_connections do
          it { should match connections }
        end
      end
    end
  else
    describe 'Verify IPV6 status: IPV6 is not enabled on the system' do
      it { expect(ipv6_status_system).to match(/ipv6 disabled/i) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_4.3.3.4_Ensure_ip6tables_firewall_rules_exist_for_all_open_ports' do
  title 'Ensure ip6tables firewall rules exist for all open ports'
  desc  "
    Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.

    **Note:**

    * Changing firewall settings while connected over network can result in being locked out of the system
    * Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well
    * The remediation command opens up the port to traffic from all sources. Consult iptables documentation and set any restrictions in compliance with site policy

    Rationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports.
  "
  impact 1.0
  only_if('This control require sudo permission to execute & applies only to environments using iptables as firewall utility.') { bash('id').stdout =~ /uid\=0\(root\)/ && firewall_utility == 'iptables' }
  if ipv6_status_system.match?(/IPv6 is enabled/) == true
    port.where { protocol =~ /.*/ && port >= 0 && address =~ /^(?!127\.0\.0\.1|::1|::).*$/ }.entries.each do |entry|
      rule_inbound = "-A INPUT -p #{entry[:protocol]} -m #{entry[:protocol]} --dport #{entry[:port]} -m state --state NEW -j ACCEPT"
      describe ip6tables do
        it { should have_rule(rule_inbound) }
      end
    end
  else
    describe 'Verify IPV6 status: IPV6 is not enabled on the system' do
      it { expect(ipv6_status_system).to match(/ipv6 disabled/i) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.1_Ensure_permissions_on_etcsshsshd_config_are_configured' do
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  desc  "
    The file /etc/ssh/sshd_config , and files ending in .conf in the /etc/ssh/sshd_config.d directory, contain configuration specifications for sshd .

    Rationale: configuration specifications for sshd need to be protected from unauthorized changes by non-privileged users.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        it { should exist }
        its('owner') { should eq 'root' }
        its('group') { should eq 'root' }
        it { should_not be_more_permissive_than('0600') }
      end
    end
    describe 'This recommendation cannot be checked automatically:' do
      skip('This recommendation requires manual review: - IF - other locations are listed in an Include statement, *.conf files in these locations should also be checked for below:
      1 Mode 0600 or more restrictive.
      2 Owned by the root user.
      3 Group owned by the group root.')
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.2_Ensure_permissions_on_SSH_private_host_key_files_are_configured' do
  title 'Ensure permissions on SSH private host key files are configured'
  desc  "
    An SSH private key is one of two files used in SSH public key authentication.  In this authentication method, the possession of the private key is proof of identity. Only a private key that corresponds to a public key will be able to authenticate successfully. The private keys need to be stored and handled carefully, and no copies of the private key should be distributed.

    Rationale: If an unauthorized user obtains the private SSH host key file, the host could be impersonated
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe.one do
    describe bash('{    a_output=(); a_output2=();    l_ssh_group_name="$(awk -F: \'($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}\' /etc/group)";    f_file_chk()    {       while IFS=: read -r l_file_mode l_file_owner l_file_group; do          a_out2=();          [ "$l_file_group" = "$l_ssh_group_name" ] && l_pmask="0137" || l_pmask="0177";          l_maxperm="$( printf \'%o\' $(( 0777 & ~$l_pmask )) )";          if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then             a_out2+=("    Mode: \"$l_file_mode\" should be mode: \"$l_maxperm\" or more restrictive");          fi;          if [ "$l_file_owner" != "root" ]; then             a_out2+=("    Owned by: \"$l_file_owner\" should be owned by \"root\"");          fi;          if [[ ! "$l_file_group" =~ ($l_ssh_group_name|root) ]]; then             a_out2+=("    Owned by group \"$l_file_group\" should be group owned by: \"$l_ssh_group_name\" or \"root\"");          fi;          if [ "${#a_out2[@]}" -gt "0" ]; then             a_output2+=("  - File: \"$l_file\"${a_out2[@]}");          else             a_output+=("  - File: \"$l_file\""             "    Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\" and group owner: \"$l_file_group\" configured");          fi;       done < <(stat -Lc \'%#a:%U:%G\' "$l_file");    };    while IFS= read -r -d $\'\0\' l_file; do        if ssh-keygen -lf &>/dev/null "$l_file"; then           file "$l_file" | grep -Piq -- \'\bopenssh\h+([^#\n\r]+\h+)?private\h+key\b\' && f_file_chk;       fi;    done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null);    if [ "${#a_output2[@]}" -le 0 ]; then       printf \'%s\n\' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" "";    else       printf \'%s\n\' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}";       [ "${#a_output[@]}" -gt 0 ] && printf \'%s\n\' "" "- Correctly set:" "${a_output[@]}" "";    fi; }').stdout do
      it { should match('PASS') }
    end
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.3_Ensure_permissions_on_SSH_public_host_key_files_are_configured' do
  title 'Ensure permissions on SSH public host key files are configured'
  desc  "
    An SSH public key is one of two files used in SSH public key authentication. In this authentication method, a public key is a key that can be used for verifying digital signatures generated using a corresponding private key. Only a public key that corresponds to a private key will be able to authenticate successfully.

    Rationale: If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe.one do
    describe bash('{    a_output=(); a_output2=();    l_pmask="0133"; l_maxperm="$( printf \'%o\' $(( 0777 & ~$l_pmask )) )";    f_file_chk()    {       while IFS=: read -r l_file_mode l_file_owner l_file_group; do          a_out2=();          if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then             a_out2+=("    Mode: \"$l_file_mode\" should be mode: \"$l_maxperm\" or more restrictive");          fi;          if [ "$l_file_owner" != "root" ]; then             a_out2+=("    Owned by: \"$l_file_owner\" should be owned by: \"root\"");          fi;          if [ "$l_file_group" != "root" ]; then             a_out2+=("    Owned by group \"$l_file_group\" should be group owned by group: \"root\"");          fi;          if [ "${#a_out2[@]}" -gt "0" ]; then             a_output2+=("  - File: \"$l_file\"" "${a_out2[@]}");          else             a_output+=("  - File: \"$l_file\""             "    Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\" and group owner: \"$l_file_group\" configured");          fi;       done < <(stat -Lc \'%#a:%U:%G\' "$l_file");    };    while IFS= read -r -d $\'\0\' l_file; do        if ssh-keygen -lf &>/dev/null "$l_file"; then           file "$l_file" | grep -Piq -- \'\bopenssh\h+([^#\n\r]+\h+)?public\h+key\b\' && f_file_chk;       fi;    done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null);    if [ "${#a_output2[@]}" -le 0 ]; then       [ "${#a_output[@]}" -le 0 ] && a_output+=("  - No openSSH public keys found");       printf \'%s\n\' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" "";    else       printf \'%s\n\' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}";       [ "${#a_output[@]}" -gt 0 ] && printf \'%s\n\' "" "- Correctly set:" "${a_output[@]}" "";    fi; }').stdout do
      it { should match('PASS') }
    end
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.4_Ensure_sshd_access_is_configured' do
  title 'Ensure sshd access is configured'
  desc  "
    There are several options available to limit which users and group can access the system via SSH. It is recommended that at least one of the following options be leveraged:

    * AllowUsers : *  The AllowUsers variable gives the system administrator the option of allowing specific users to ssh into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.
    * AllowGroups : *  The AllowGroups variable gives the system administrator the option of allowing specific groups of users to ssh into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.
    * DenyUsers : *  The DenyUsers variable gives the system administrator the option of denying specific users to ssh into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.
    * DenyGroups : *  The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.

    Rationale: Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = lport == 'NOT_SET' ? "sshd -T | grep -Pi -- '^(allow|deny)(users|groups)'" : "sshd -T -C lport=#{lport} | grep -Pi -- '^(allow|deny)(users|groups)'"
    describe 'SSHD Configuration: access' do
      it { expect(command(cmd).stdout.strip).to(match(/^(allowusers|allowgroups|denyusers|denygroups)\s+(\S+).*$/)) }
    end
    unless match_directives_parameter_sets.empty?
      match_directives_parameter_sets.each do |match_directives_parameter_set|
        cmd_match_directive = if match_directives_parameter_set.match(/lport/) || lport == 'NOT_SET'
                                "sshd -T #{match_directives_parameter_set} | grep -Pi -- '^(allow|deny)(users|groups)'"
                              else
                                "sshd -T -C lport=#{lport} #{match_directives_parameter_set} | grep -Pi -- '^(allow|deny)(users|groups)'"
                              end
        describe 'Configuration in Match Directive: access' do
          it { expect(command(cmd_match_directive).stdout.strip).to(match(/^(allowusers|allowgroups|denyusers|denygroups)\s+(\S+).*$/)) }
        end
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.5_Ensure_sshd_Banner_is_configured' do
  title 'Ensure sshd Banner is configured'
  desc  "
    The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed.

    Rationale: Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? "sshd -T | grep -Pi -- '^banner\s+'" : "sshd -T #{match_directives_parameters} | grep -Pi -- '^banner\s+'"
    describe command(cmd).stdout.to_s.strip do
      it { should match('banner\s+\/\S+') }
    end
    banner_file = command(cmd).stdout.to_s.strip.split[1]
    appropriate_banner_message = required_banner_message == 'NOT_SET' ? 'Authorized users only. All activity may be monitored and reported.' : required_banner_message

    describe file(banner_file) do
      it { should exist }
      its('content') { should match(appropriate_banner_message) }
    end
    matching_text = file(banner_file).content.match(appropriate_banner_message) || ['file does not match banner']
    describe matching_text[0] do
      it { should eq file(banner_file).content.strip }
    end

    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/^(?i)\s*Banner\s+\"?none\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.6_Ensure_sshd_Ciphers_are_configured' do
  title 'Ensure sshd Ciphers are configured'
  desc  "
    This variable limits the ciphers that SSH can use during communication.

    **Notes:**

    * Some organizations may have stricter requirements for approved ciphers.
    * Ensure that ciphers used are in compliance with site policy.
    *  The only \"strong\" ciphers currently FIPS 140 compliant are: * [aes256-gcm@openssh.com](mailto:aes256-gcm@openssh.com)
    * [aes128-gcm@openssh.com](mailto:aes128-gcm@openssh.com)
    * aes256-ctr
    * aes192-ctr
    * aes128-ctr

    Rationale: Weak ciphers  that are used for authentication to the cryptographic module cannot be relied upon to provide confidentiality or integrity, and system data may be compromised.

    * The Triple DES ciphers, as used in SSH, have a birthday bound of approximately four billion blocks, which makes it easier for remote attackers to obtain clear text data via a birthday attack against a long-duration encrypted session, aka a \"Sweet32\" attack.
    * Error handling in the SSH protocol; Client and Server, when using a block cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for remote attackers to recover certain plain text data from an arbitrary block of cipher text in an SSH session via unknown vectors.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    weak_ciphers = %w(3des-cbc aes128-cbc aes192-cbc aes256-cbc arcfour arcfour128 arcfour256 blowfish-cbc cast128-cbc rijndael-cbc@lysator.liu.se)
    cmd = lport == 'NOT_SET' ? "sshd -T | grep -Pi -- '^ciphers'" : "sshd -T -C lport=#{lport} | grep -Pi -- '^ciphers'"
    current_ciphers = command("#{cmd} | awk '{ print $2 }'").stdout.strip.split(',')
    weak_ciphers_in_current_ciphers = weak_ciphers & current_ciphers
    describe 'sshd Ciphers are configured not to have any weak Ciphers' do
      it { expect(weak_ciphers_in_current_ciphers).to(be_empty) }
    end
    if current_ciphers.include?('chacha20-poly1305@openssh.com')
      describe 'This recommendation cannot be checked automatically:' do
        skip('This recommendation requires manual review. As the output includes chacha20-poly1305@openssh.com, review CVE-2023-48795 and verify the system has been patched.')
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.7_Ensure_sshd_ClientAliveInterval_and_ClientAliveCountMax_are_configured' do
  title 'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured'
  desc  "
    **Note:** To clarify, the two settings described below are only meant for idle connections from a protocol perspective and are not meant to check if the user is active or not. An idle user does not mean an idle connection. SSH does not and never had, intentionally, the capability to drop idle users. In SSH versions before 8.2p1 there was a bug that caused these values to behave in such a manner that they were abused to disconnect idle users. This bug has been resolved in 8.2p1 and thus it can no longer be abused disconnect idle users.

    The two options ClientAliveInterval and ClientAliveCountMax control the timeout of SSH sessions. Taken directly from man 5 sshd_config :

    * ClientAliveInterval Sets a timeout interval in seconds after which if no data has been received from the client, sshd(8) will send a message through the encrypted channel to request a response from the client. The default is 0, indicating that these messages will not be sent to the client.

    * ClientAliveCountMax Sets the number of client alive messages which may be sent without sshd(8) receiving any messages back from the client. If this threshold is reached while client alive messages are being sent, sshd will disconnect the client, terminating the session.  It is important to note that the use of client alive messages is very different from TCPKeepAlive. The client alive messages are sent through the encrypted channel and therefore will not be spoofable. The TCP keepalive option en&#x2010;abled by TCPKeepAlive is spoofable. The client alive mechanism is valuable when the client or server depend on knowing when a connection has become unresponsive.
    The default value is 3. If ClientAliveInterval is set to 15, and ClientAliveCountMax is left at the default, unresponsive SSH clients will be disconnected after approximately 45 seconds. Setting a zero ClientAliveCountMax disables connection termination.

    Rationale: In order to prevent resource exhaustion, appropriate values should be set for both ClientAliveInterval and ClientAliveCountMax . Specifically, looking at the source code, ClientAliveCountMax must be greater than zero in order to utilize the ability of SSH to drop idle connections. If connections are allowed to stay open indefinitely, this can potentially be used as a DDOS attack or simple resource exhaustion could occur over unreliable networks.

    The example set here is a 45 second timeout. Consult your site policy for network timeouts and apply as appropriate.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd1 = match_directives_parameters == 'NOT_SET' ? "sshd -T | grep -Pi -- clientaliveinterval | awk '{print $2}'" : "sshd -T #{match_directives_parameters} | grep -Pi -- clientaliveinterval | awk '{print $2}'"
    cmd2 = match_directives_parameters == 'NOT_SET' ? "sshd -T | grep -Pi -- clientalivecountmax | awk '{print $2}'" : "sshd -T #{match_directives_parameters} | grep -Pi -- clientalivecountmax | awk '{print $2}'"
    describe 'ClientAliveInterval' do
      it { expect(command(cmd1).stdout.strip.to_i).to(be > 0) }
    end
    describe 'ClientAliveCountMax' do
      it { expect(command(cmd2).stdout.strip.to_i).to(be > 0) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/(?i)^\s*ClientAliveInterval\s+"?0\b/) }
        its('content') { should_not match(/(?i)^\s*ClientAliveCountMax\s+"?0\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.10_Ensure_sshd_HostbasedAuthentication_is_disabled' do
  title 'Ensure sshd HostbasedAuthentication is disabled'
  desc  "
    The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts , or /etc/hosts.equiv , along with successful public key client host authentication.

    Rationale: Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf , disabling the ability to use .rhosts files in SSH provides an additional layer of protection.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? 'sshd -T | grep hostbasedauthentication' : "sshd -T #{match_directives_parameters} | grep hostbasedauthentication"
    describe command(cmd).stdout.strip do
      it { should match(/^\s*hostbasedauthentication\s+no\s*$/) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/^(?i)\s*HostbasedAuthentication\s+"?yes"?\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.11_Ensure_sshd_IgnoreRhosts_is_enabled' do
  title 'Ensure sshd IgnoreRhosts is enabled'
  desc  "
    The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication .

    Rationale: Setting this parameter forces users to enter a password when authenticating with SSH.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? 'sshd -T | grep ignorerhosts' : "sshd -T #{match_directives_parameters} | grep ignorerhosts"
    describe command(cmd).stdout.strip do
      it { should match(/^\s*ignorerhosts\s+yes\s*$/) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/^(?i)\s*ignorerhosts\s+"?no"?\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.12_Ensure_sshd_KexAlgorithms_is_configured' do
  title 'Ensure sshd KexAlgorithms is configured'
  desc  "
    Key exchange is any method in cryptography by which cryptographic keys are exchanged between two parties, allowing use of a cryptographic algorithm. If the sender and receiver wish to exchange encrypted messages, each must be equipped to encrypt messages to be sent and decrypt messages received

    **Notes:**

    * Kex algorithms have a higher preference the earlier they appear in the list
    * Some organizations may have stricter requirements for approved Key exchange algorithms
    * Ensure that Key exchange algorithms used are in compliance with site policy
    *  The only Key Exchange Algorithms currently FIPS 140 approved are: * ecdh-sha2-nistp256
    * ecdh-sha2-nistp384
    * ecdh-sha2-nistp521
    * diffie-hellman-group-exchange-sha256
    * diffie-hellman-group16-sha512
    * diffie-hellman-group18-sha512
    * diffie-hellman-group14-sha256

    Rationale: Key exchange methods that are considered weak should be removed. A key exchange method may be weak because too few bits are used, or the hashing algorithm is considered too weak.  Using weak algorithms could expose connections to man-in-the-middle attacks
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    weak_kex = %w(diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1)
    current_kex = command('sshd -T | grep -Pi \'kexalgorithms\' | awk \'{ print $2 }\'').stdout.strip.split(',')
    weak_kex_in_current_kex = weak_kex & current_kex
    describe 'sshd KexAlgorithms are configured not to have any weak KexAlgorithms' do
      it { expect(weak_kex_in_current_kex).to(be_empty) }
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.13_Ensure_sshd_LoginGraceTime_is_configured' do
  title 'Ensure sshd LoginGraceTime is configured'
  desc  "
    The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server. The longer the Grace period is the more open unauthenticated connections can exist. Like other session controls in this session the Grace Period should be limited to appropriate organizational limits to ensure the service is available for needed access.

    Rationale: Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. It will also limit the number of concurrent unauthenticated connections While the recommended setting is 60 seconds (1 Minute), set the number based on site policy.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    describe command('sshd -T | grep logingracetime').stdout.strip do
      it { should match(/^\s*logingracetime\s+([1-9]|[1-5][0-9]|60)$/) }
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.14_Ensure_sshd_LogLevel_is_configured' do
  title 'Ensure sshd LogLevel is configured'
  desc  "
    SSH provides several logging levels with varying amounts of verbosity. The DEBUG options are specifically not recommended other than strictly for debugging SSH communications. These levels provide so much data that it is difficult to identify important security information, and may violate the privacy of users.

    Rationale: The INFO level is the basic level that only records login activity of SSH users. In many situations, such as Incident Response, it is important to determine when a particular user was active on a system. The logout record can eliminate those users who disconnected, which helps narrow the field.

    The VERBOSE level specifies that login and logout activity as well as the key fingerprint for any SSH key used for login will be logged. This information is important for SSH key management, especially in legacy environments.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? 'sshd -T | grep loglevel' : "sshd -T #{match_directives_parameters} | grep loglevel"
    describe command(cmd).stdout.strip do
      it { should match(/^\s*loglevel\s+VERBOSE|INFO\s*$/) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/^(?i)\s*LogLevel\s+\"?(QUIET|FATAL|ERROR|DEBUG|DEBUG1|DEBUG2|DEBUG3)\"?\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.15_Ensure_sshd_MACs_are_configured' do
  title 'Ensure sshd MACs are configured'
  desc  "
    This variable limits the types of MAC algorithms that SSH can use during communication.

    **Notes:**

    * Some organizations may have stricter requirements for approved MACs.
    * Ensure that MACs used are in compliance with site policy.
    *  The only \"strong\" MACs currently FIPS 140 approved are: * HMAC-SHA1
    * HMAC-SHA2-256
    * HMAC-SHA2-384
    * HMAC-SHA2-512

    Rationale: MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability in SSH downgrade attacks. Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and capture credentials and information.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    weak_macs = %w(hmac-md5 hmac-md5-96 hmac-ripemd160 hmac-sha1-96 umac-64@openssh.com hmac-md5-etm@openssh.com hmac-md5-96-etm@openssh.com hmac-ripemd160-etm@openssh.com hmac-sha1-96-etm@openssh.com umac-64-etm@openssh.com umac-128-etm@openssh.com)
    cmd = lport == 'NOT_SET' ? "sshd -T | grep -Pi -- '^macs'" : "sshd -T -C lport=#{lport} | grep -Pi -- '^macs'"
    current_macs = command("#{cmd} | awk '{ print $2 }'").stdout.strip.split(',')
    weak_macs_in_current_macs = weak_macs & current_macs
    describe 'sshd MACs are configured not to have any weak MACs' do
      it { expect(weak_macs_in_current_macs).to(be_empty) }
    end
    describe 'This recommendation cannot be checked automatically:' do
      skip('This recommendation requires manual review: Review CVE-2023-48795 and verify the system has been patched. If the system has not been patched, review the use of the Encrypt Then Mac (etm) MACs.')
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.16_Ensure_sshd_MaxAuthTries_is_configured' do
  title 'Ensure sshd MaxAuthTries is configured'
  desc  "
    The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. When the login failure count reaches half the number, error messages will be written to the syslog file detailing the login failure.

    Rationale: Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, set the number based on site policy.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? 'sshd -T | grep maxauthtries' : "sshd -T #{match_directives_parameters} | grep maxauthtries"
    describe command(cmd).stdout.strip do
      it { should match(/^\s*maxauthtries\s+[0-4]$/) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/^(?i)\s*maxauthtries\s+([5-9]|[1-9][0-9]+)/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.17_Ensure_sshd_MaxSessions_is_configured' do
  title 'Ensure sshd MaxSessions is configured'
  desc  "
    The MaxSessions parameter specifies the maximum number of open sessions permitted from a given connection.

    Rationale: To protect a system from denial of service due to a large number of concurrent sessions, use the rate limiting function of MaxSessions to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? 'sshd -T | grep -i maxsessions' : "sshd -T #{match_directives_parameters} | grep -i maxsessions"
    describe command(cmd).stdout.strip do
      it { should match(/^\s*maxsessions\s+([1-9]|10)\s*$/) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/(?i)^\s*MaxSessions\s+"?(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.18_Ensure_sshd_MaxStartups_is_configured' do
  title 'Ensure sshd MaxStartups is configured'
  desc  "
    The MaxStartups parameter specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.

    Rationale: To protect a system from denial of service due to a large number of pending authentication connection attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = lport == 'NOT_SET' ? "sshd -T | grep -Pi -- '^maxstartups'" : "sshd -T -C lport=#{lport} | grep -Pi -- '^maxstartups'"
    describe 'SSHD Configuration: MaxStartups' do
      it { expect(command(cmd).stdout.strip).to(match(/^\s*maxstartups\s+(10|[1-9])\S(30|[1-2][0-9]|[1-9])\S(60|[1-5][0-9]|[1-9])\s*$/)) }
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.19_Ensure_sshd_PermitEmptyPasswords_is_disabled' do
  title 'Ensure sshd PermitEmptyPasswords is disabled'
  desc  "
    The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings.

    Rationale: Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? 'sshd -T | grep permitemptypasswords' : "sshd -T #{match_directives_parameters} | grep permitemptypasswords"
    describe command(cmd).stdout.strip do
      it { should match(/^\s*permitemptypasswords\s+no$/) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/^(?i)\s*PermitEmptyPasswords\s+\"?yes\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.20_Ensure_sshd_PermitRootLogin_is_disabled' do
  title 'Ensure sshd PermitRootLogin is disabled'
  desc  "
    The PermitRootLogin parameter specifies if the root user can log in using SSH. The default is prohibit-password .

    Rationale: Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root . This limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    cmd = match_directives_parameters == 'NOT_SET' ? 'sshd -T | grep permitrootlogin' : "sshd -T #{match_directives_parameters} | grep permitrootlogin"
    describe command(cmd).stdout.strip do
      it { should match(/^\s*permitrootlogin\s+no$/) }
    end
    ssh_config_files = command("find /etc/ssh/sshd_config.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/ssh/sshd_config']
    ssh_config_files.each do |file_path|
      describe file(file_path) do
        its('content') { should_not match(/^(?i)\s*PermitRootLogin\s+"?(yes|prohibit-password|forced-commands-only)"?\b/) }
      end
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.21_Ensure_sshd_PermitUserEnvironment_is_disabled' do
  title 'Ensure sshd PermitUserEnvironment is disabled'
  desc  "
    The PermitUserEnvironment option allows users to present environment options to the SSH daemon.

    Rationale: Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has SSH executing trojan'd programs)
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    describe sshd_config do
      its('PermitUserEnvironment') { should eq 'no' }
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.1.22_Ensure_sshd_UsePAM_is_enabled' do
  title 'Ensure sshd UsePAM is enabled'
  desc  "
    The UsePAM directive enables the Pluggable Authentication Module (PAM) interface. If set to yes this will enable PAM authentication using ChallengeResponseAuthentication and PasswordAuthentication directives in addition to PAM account and session module processing for all authentication types.

    Rationale: When usePAM is set to yes , PAM runs through account and session types properly. This is important if you want to restrict access to services based off of IP, time or other factors of the account. Additionally, you can make sure users inherit certain environment variables on login or disallow access to the server
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  if package('openssh-server').installed?
    describe sshd_config do
      its('UsePAM') { should eq 'yes' }
    end
  else
    describe package('openssh-server') do
      it { should_not be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.2.1_Ensure_sudo_is_installed' do
  title 'Ensure sudo is installed'
  desc  "
    sudo allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.  The invoking user's real (not effective) user ID is used to determine the user name with which to query the security policy.

    Rationale: sudo supports a plug-in architecture for security policies and input/output logging.  Third parties can develop and distribute their own policy and I/O logging plug-ins to work seamlessly with the sudo front end. The default security policy is sudoers , which is configured via the file /etc/sudoers and any entries in /etc/sudoers.d .

    The security policy determines what privileges, if any, a user has to run sudo . The policy may require that users authenticate themselves with a password or another authentication mechanism. If authentication is required, sudo will exit if the user's password is not entered within a configurable time limit. This limit is policy-specific.
  "
  impact 1.0
  describe.one do
    describe package('sudo') do
      it { should be_installed }
    end
    describe package('sudo-ldap') do
      it { should be_installed }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.2.2_Ensure_sudo_commands_use_pty' do
  title 'Ensure sudo commands use pty'
  desc  "
    sudo can be configured to run only from a pseudo terminal ( pseudo-pty ).

    Rationale: Attackers can run a malicious program using sudo which would fork a background process that remains even when the main program has finished executing.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/sudoers.d/ -type f -regex ^.+$').stdout.split + ['/etc/sudoers']
  files_with_correct_conf = files.reject { |f| file(f).content !~ /^(?i)\s*Defaults\s+([^#\n\r]+,\s*)?use_pty\b/ }
  describe "Files in which 'Defaults use_pty' is set" do
    it { expect(files_with_correct_conf).not_to(be_empty) }
  end
  files_with_wrong_conf = files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^(?i)\s*Defaults\s+([^#\n\r]+,\s*)?\!use_pty\b/ }
  describe "Files in which 'Defaults !use_pty' is set" do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.2.3_Ensure_sudo_log_file_exists' do
  title 'Ensure sudo log file exists'
  desc  "
    sudo can use a custom log file

    Rationale: A sudo log file simplifies auditing of sudo commands
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/sudoers.d/ -type f -regex ^.+$').stdout.split + ['/etc/sudoers']
  files_with_correct_conf = files.reject { |f| file(f).content !~ /^(?i)\s*Defaults\s+([^#]+,\s*)?logfile\s*=\s*(\"|\')?\S+(\"|\')?(,\s*\S+\s*)*\s*(#.*)?$/ }
  describe "Files in which 'Defaults logfile' is set" do
    it { expect(files_with_correct_conf).not_to(be_empty) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.2.5_Ensure_re-authentication_for_privilege_escalation_is_not_disabled_globally' do
  title 'Ensure re-authentication for privilege escalation is not disabled globally'
  desc  "
    The operating system must be configured so that users must re-authenticate for privilege escalation.

    Rationale: Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

    When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/sudoers.d/ -type f -regex ^.+$').stdout.split + ['/etc/sudoers']
  files_with_wrong_conf = files.reject { |f| file(f).content !~ /(?i)^\s*([^#\n\r]+\s+)?\!authenticate\b(\.*)?$/ }
  describe "Files in which '!authenticate' tag is set" do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.2.6_Ensure_sudo_authentication_timeout_is_configured_correctly' do
  title 'Ensure sudo authentication timeout is configured correctly'
  desc  "
    sudo caches used credentials for a default of 15 minutes. This is for ease of use when there are multiple administrative tasks to perform. The timeout can be modified to suit local security policies.

    This default is distribution specific. See audit section for further information.

    Rationale: Setting a timeout value reduces the window of opportunity for unauthorized privileged access to another user.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command("find /etc/sudoers.d/ -type f -regex ^.+\.conf$").stdout.split + ['/etc/sudoers']
  files_with_wrong_conf = files.reject { |f| file(f).content !~ /(?i)^\s*defaults\s+(?:[^#\n\r]+\s*,\s*)?timestamp_timeout=(-1|1[6-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b(\s*,\s*.*)?$/ }
  describe 'Files in which parameter: timestamp_timeout has wrongly configured value' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.2.7_Ensure_access_to_the_su_command_is_restricted' do
  title 'Ensure access to the su command is restricted'
  desc  "
    The su command allows a user to run a command or shell as another user. The program has been superseded by sudo , which allows for more granular control over privileged access. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su , the su command will only allow users in a specific groups to execute su . This group should be empty to reinforce the use of sudo for privileged access.

    Rationale: Restricting the use of su , and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo , whereas su can only record that a user executed the su program.
  "
  impact 1.0
  if su_group_name == 'NOT_SET'
    describe 'This control cannot be checked automatically as the su_group_name is not set.' do
      skip('Set the su_group_name attribute to a valid group name to check this control.')
    end
  else
    describe file('/etc/pam.d/su') do
      its('content') { should match(/(?i)^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so\s+(?:[^#\n\r]+\s+)?((?!\2)(use_uid\b|group=#{su_group_name}\b))\s+(?:[^#\n\r]+\s+)?((?!\1)(use_uid\b|group=#{su_group_name}\b))(\s+.*)?$/) }
    end
    describe etc_group.groups do
      it { should include su_group_name }
    end
    users_in_group = etc_group.where(group_name: "#{su_group_name}").users
    describe "Users in group: #{su_group_name}" do
      it { expect(users_in_group).to(be_empty) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.1.1_Ensure_latest_version_of_pam_is_installed' do
  title 'Ensure latest version of pam is installed'
  desc  "
    Updated versions of PAM include additional functionality

    Rationale: To ensure the system has full functionality and access to the options covered by this Benchmark the latest version of libpam-runtime should be installed on the system
  "
  impact 1.0
  describe package('libpam-runtime') do
    its('version') { should cmp >= '1.4.0-11ubuntu2.6' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.1.2_Ensure_libpam-modules_is_installed' do
  title 'Ensure libpam-modules is installed'
  desc  "
    Pluggable Authentication Modules for PAM

    Rationale: To ensure the system has full functionality and access to the PAM options covered by this Benchmark
  "
  impact 1.0
  describe package('libpam-modules') do
    its('version') { should cmp >= '1.4.0-11ubuntu2.6' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.1.3_Ensure_libpam-pwquality_is_installed' do
  title 'Ensure libpam-pwquality is installed'
  desc  "
    libpwquality provides common functions for password quality checking and scoring them based on their apparent randomness. The library also provides a function for generating random passwords with good pronounceability.

    This module can be plugged into the password stack of a given service to provide some plug-in strength-checking for passwords. The code was originally based on pam_cracklib module and the module is backwards compatible with its options.

    Rationale: Strong passwords reduce the risk of systems being hacked through brute force methods.
  "
  impact 1.0
  describe package('libpam-pwquality') do
    it { should be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.2.1_Ensure_pam_unix_module_is_enabled' do
  title 'Ensure pam_unix module is enabled'
  desc  "
    pam_unix is the standard Unix authentication module. It uses standard calls from the system's libraries to retrieve and set account information as well as authentication. Usually this is obtained from the /etc/passwd and if shadow is enabled, the /etc/shadow file as well.

    The account component performs the task of establishing the status of the user's account and password based on the following shadow elements: expire , last_change , max_change , min_change , warn_change . In the case of the latter, it may offer advice to the user on changing their password or, through the PAM_AUTHTOKEN_REQD return, delay giving service to the user until they have established a new password. The entries listed above are documented in the shadow(5) manual page. Should the user's record not contain one or more of these entries, the corresponding shadow check is not performed.

    The authentication component performs the task of checking the users credentials (password). The default action of this module is to not permit the user access to a service if their official password is blank.

    Rationale: The system should only provide access after performing authentication of a user.
  "
  impact 1.0
  describe file('/etc/pam.d/common-account') do
    its('content') { should match(/^\s*account\s+[^#\n\r]+\s+pam_unix\.so\b/) }
  end
  describe file('/etc/pam.d/common-session') do
    its('content') { should match(/^\s*session\s+[^#\n\r]+\s+pam_unix\.so\b/) }
  end
  describe file('/etc/pam.d/common-auth') do
    its('content') { should match(/^\s*auth\s+[^#\n\r]+\s+pam_unix\.so\b/) }
  end
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/^\s*password\s+[^#\n\r]+\s+pam_unix\.so\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.2.2_Ensure_pam_faillock_module_is_enabled' do
  title 'Ensure pam_faillock module is enabled'
  desc  "
    The pam_faillock.so module maintains a list of failed authentication attempts per user during a specified interval and locks the account in case there were more than the configured number of consecutive failed authentications (this is defined by the deny parameter in the faillock configuration). It stores the failure records into per-user files in the tally directory.

    Rationale: Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  impact 1.0
  describe file('/etc/pam.d/common-auth') do
    its('content') { should match(/(?i)^\s*auth\s+([^#\n\r]+)\s+pam_faillock\.so\s+([^#\n\r]+\s+)?preauth\b/) }
    its('content') { should match(/(?i)^\s*auth\s+([^#\n\r]+)\s+pam_faillock\.so\s+([^#\n\r]+\s+)?authfail\b/) }
  end
  describe file('/etc/pam.d/common-account') do
    its('content') { should match(/(?i)^\s*account\s+([^#\n\r]+)\s+pam_faillock\.so\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.2.3_Ensure_pam_pwquality_module_is_enabled' do
  title 'Ensure pam_pwquality module is enabled'
  desc  "
    The pam_pwquality.so module performs password quality checking. This module can be plugged into the password stack of a given service to provide strength-checking for passwords. The code was originally based on pam_cracklib module and the module is backwards compatible with its options.

    The action of this module is to prompt the user for a password and check its strength against a system dictionary and a set of rules for identifying poor choices.

    The first action is to prompt for a single password, check its strength and then, if it is considered strong, prompt for the password a second time (to verify that it was typed correctly on the first occasion). All being well, the password is passed on to subsequent modules to be installed as the new authentication token.

    Rationale: Use of a unique, complex passwords helps to increase the time and resources required to compromise the password.
  "
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/(?i)^\s*password\s+(requisite|required)\s+pam_pwquality\.so\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.2.4_Ensure_pam_pwhistory_module_is_enabled' do
  title 'Ensure pam_pwhistory module is enabled'
  desc  "
    The pam_pwhistory.so module saves the last passwords for each user in order to force password change history and keep the user from alternating between the same password too frequently.

    This module does not work together with kerberos. In general, it does not make much sense to use this module in conjunction with NIS or LDAP , since the old passwords are stored on the local machine and are not available on another machine for password history checking.

    Rationale: Use of a unique, complex passwords helps to increase the time and resources required to compromise the password.
  "
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/(?i)^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.1.1_Ensure_password_failed_attempts_lockout_is_configured' do
  title 'Ensure password failed attempts lockout is configured'
  desc  "
    The deny=
    <n> option will deny access if the number of consecutive authentication failures for this user during the recent interval exceeds **** .</n>

    Rationale: Locking out user IDs after **n** unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  impact 1.0
  describe file('/etc/security/faillock.conf') do
    its('content') { should match(/(?i)^\s*deny\s*=\s*[1-5]\b/) }
  end
  describe file('/etc/pam.d/common-auth') do
    its('content') { should_not match(/(?i)^\s*auth\s+(requisite|required|sufficient)\s+pam_faillock\.so\s+([^#\n\r]+\s+)?deny\s*=\s*(0|[6-9]|[1-9][0-9]+)\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.1.2_Ensure_password_unlock_time_is_configured' do
  title 'Ensure password unlock time is configured'
  desc  "
    unlock_time=
    <n> - The access will be re-enabled after **** seconds after the lock out. The value 0 has the same meaning as value never - the access will not be re-enabled without resetting the faillock entries by the faillock(8) command.

    **Note:**

    * The default directory that pam_faillock uses is usually cleared on system boot so the access will be also re-enabled after system reboot. If that is undesirable a different tally directory must be set with the dir option.
    * It is usually undesirable to permanently lock out users as they can become easily a target of denial of service attack unless the usernames are random and kept secret to potential attackers.
    *  The maximum configurable value for unlock_time is 604800</n>

    Rationale: Locking out user IDs after **n** unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  impact 1.0
  describe file('/etc/security/faillock.conf') do
    its('content') { should match(/(?i)^\s*unlock_time\s*=\s*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b/) }
  end
  describe file('/etc/pam.d/common-auth') do
    its('content') { should_not match(/(?i)^\s*auth\s+(requisite|required|sufficient)\s+pam_faillock\.so\s+([^#\n\r]+\s+)?unlock_time\s*=\s*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.1_Ensure_password_number_of_changed_characters_is_configured' do
  title 'Ensure password number of changed characters is configured'
  desc  "
    The pwqualitydifok option sets the number of characters in a password that must not be present in the old password.

    Rationale: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*difok\s*=\s*([0-1])\b/) }
  describe 'Files in which parameter: difok has wrongly configured value' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
  files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*difok\s*=\s*([2-9]|[1-9][0-9]+)\b/) }
  describe 'Files in which parameter: difok has correctly configured value' do
    it { expect(files_with_correct_conf).not_to(be_empty) }
  end
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match(/(?i)^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so\s+([^#\n\r]+\s+)?difok\s*=\s*([0-1])\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.2_Ensure_minimum_password_length_is_configured' do
  title 'Ensure minimum password length is configured'
  desc  "
    The minimum password length setting determines the lowers number of characters that make up a password for a user account. There are many different theories about how to determine the best password length for an organization, but perhaps \"passphrase\" is a better term than \"password\".

    The minlen option sets the minimum acceptable size for the new password (plus one if credits are not disabled which is the default). Cannot be set to lower value than 6.

    Rationale: Strong passwords help protect systems from password attacks. Types of password attacks include dictionary attacks, which attempt to use common words and phrases, and brute force attacks, which try every possible combination of characters. Also attackers may try to obtain the account database so they can use tools to discover the accounts and passwords.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*minlen\s*=\s*(1[0-3]|[0-9])\b/) }
  describe 'Files in which parameter: minlen has wrongly configured value' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
  files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b/) }
  describe 'Files in which parameter: minlen has correctly configured value' do
    it { expect(files_with_correct_conf).not_to(be_empty) }
  end
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match(/(?i)^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so\s+([^#\n\r]+\s+)?minlen\s*=\s*([0-9]|1[0-3])\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.3_Ensure_password_complexity_is_configured' do
  title 'Ensure password complexity is configured'
  desc  "
    Password complexity can be set through:

    * minclass - The minimum number of classes of characters required in a new password. (digits, uppercase, lowercase, others). e.g. minclass = 4 requires digits, uppercase, lower case, and special characters.
    * dcredit - The maximum credit for having digits in the new password. If less than 0 it is the minimum number of digits in the new password. e.g. dcredit = -1 requires at least one digit
    * ucredit - The maximum credit for having uppercase characters in the new password. If less than 0 it is the minimum number of uppercase characters in the new password. e.g. ucredit = -1 requires at least one uppercase character
    * ocredit - The maximum credit for having other characters in the new password. If less than 0 it is the minimum number of other characters in the new password. e.g. ocredit = -1 requires at least one special character
    * lcredit - The maximum credit for having lowercase characters in the new password.  If less than 0 it is the minimum number of lowercase characters in the new password. e.g. lcredit = -1 requires at least one lowercase character

    Rationale: Strong passwords protect systems from being hacked through brute force methods.

    Requiring at least one non-alphabetic character increases the search space beyond pure dictionary words, which makes the resulting password harder to crack.

    Forcing users to choose an excessively complex password, e.g. some combination of upper-case, lower-case, numbers, and special characters, has a negative impact. It places an extra burden on users and many will use predictable patterns (for example, a capital letter in the first position, followed by lowercase letters, then one or two numbers, and a &#x201C;special character&#x201D; at the end). Attackers know this, so dictionary attacks will often contain these common patterns and use the most common substitutions like, $ for s, @ for a, 1 for l, 0 for o.
  "
  impact 0.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*(minclass\s*=\s*[0-3]|[dulo]credit\s*=\s*([1-9]|[1-9][0-9]+))\b/) }
  describe 'Files in which password complexity parameters have wrongly configured values' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
  files_with_correct_conf_minclass = files.select { |file_path| file(file_path).content.match(/(?i)^\s*minclass\s*=\s*([4-9]|[1-9][0-9]|[1-9][0-9][0-9]+)\b/) }
  credit_parameter_counter = 0
  %w(dcredit ucredit lcredit ocredit).each do |parameter|
    files_with_correct_conf_credit = files.select { |file_path| file(file_path).content.match(/(?i)^\s*#{parameter}\s*=\s*((-[1-9]+)|0)\b/) }
    unless files_with_correct_conf_credit.empty?
      credit_parameter_counter += 1
    end
  end
  describe.one do
    describe 'Files in which parameter: minclass has correctly configured value' do
      it { expect(files_with_correct_conf_minclass).not_to(be_empty) }
    end
    describe 'Files in which parameters: dcredit,ucredit,lcredit and ocredit have correctly configured values' do
      it { expect(credit_parameter_counter).to(cmp == 4) }
    end
  end
  ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth'].each do |filename|
    describe file(filename) do
      its('content') { should_not match(/(?i)^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so\s+([^#\n\r]+\s+)?(minclass\s*=\s*[0-3]|[dulo]credit\s*=\s*([1-9]|[1-9][0-9]+))\b/) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.4_Ensure_password_same_consecutive_characters_is_configured' do
  title 'Ensure password same consecutive characters is configured'
  desc  "
    The pwqualitymaxrepeat option sets the maximum number of allowed same consecutive characters in a new password.

    Rationale: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*maxrepeat\s*=\s*(0|[4-9]|[1-9][0-9]+)\b/) }
  describe 'Files in which parameter: maxrepeat has wrongly configured value' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
  files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*maxrepeat\s*=\s*[1-3]\b/) }
  describe 'Files in which parameter: maxrepeat has correctly configured value' do
    it { expect(files_with_correct_conf).not_to(be_empty) }
  end
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match(/(?i)^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so\s+([^#\n\r]+\s+)?maxrepeat\s*=\s*(0|[4-9]|[1-9][0-9]+)\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.5_Ensure_password_maximum_sequential_characters_is_configured' do
  title 'Ensure password maximum sequential characters is configured'
  desc  "
    The pwqualitymaxsequence option sets the maximum length of monotonic character sequences in the new password. Examples of such sequence are 12345 or fedcb . The check is disabled if the value is 0 .

    **Note:** Most such passwords will not pass the simplicity check unless the sequence is only a minor part of the password.

    Rationale: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*maxsequence\s*=\s*(0|[4-9]|[1-9][0-9]+)\b/) }
  describe 'Files in which parameter: maxsequence has wrongly configured value' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
  files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*maxsequence\s*=\s*[1-3]\b/) }
  describe 'Files in which parameter: maxsequence has correctly configured value' do
    it { expect(files_with_correct_conf).not_to(be_empty) }
  end
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match(/(?i)^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so\s+([^#\n\r]+\s+)?maxsequence\s*=\s*(0|[4-9]|[1-9][0-9]+)\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.6_Ensure_password_dictionary_check_is_enabled' do
  title 'Ensure password dictionary check is enabled'
  desc  "
    The pwqualitydictcheck option sets whether to check for the words from the cracklib dictionary.

    Rationale: If the operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*dictcheck\s*=\s*0\b/) }
  describe 'Files in which parameter: dictcheck has value configured to 0' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match(/(?i)^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so\s+([^#\n\r]+\s+)?dictcheck\s*=\s*0\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.7_Ensure_password_quality_checking_is_enforced' do
  title 'Ensure password quality checking is enforced'
  desc  "
    The pam_pwquality module can be configured to either reject a password if it fails the checks, or only print a warning.

    This is configured by setting the enforcing=
    <N> argument. If nonzero, a password will be rejected if it fails the checks, otherwise only a warning message will be provided.

    This setting applies only to the pam_pwquality module and possibly other applications that explicitly change their behavior based on it. It does not affect pwmake(1) and pwscore(1).</N>

    Rationale: Strong passwords help protect systems from password attacks. Types of password attacks include dictionary attacks, which attempt to use common words and phrases, and brute force attacks, which try every possible combination of characters. Also attackers may try to obtain the account database so they can use tools to discover the accounts and passwords.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*enforcing\s*=\s*0\b/) }
  describe 'Files in which parameter: enforcing has value configured to 0' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
  describe file('/etc/pam.d/common-password') do
    its('content') { should_not match(/(?i)^\s*password\s+[^#\n\r]+\s+pam_pwquality\.so\s+([^#\n\r]+\s+)?enforcing=0\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.2.8_Ensure_password_quality_is_enforced_for_the_root_user' do
  title 'Ensure password quality is enforced for the root user'
  desc  "
    If the pwqualityenforce_for_root option is enabled, the module will return error on failed check even if the user changing the password is root.

    This option is off by default which means that just the message about the failed check is printed but root can change the password anyway.

    **Note:** The root is not asked for an old password so the checks that compare the old and new password are not performed.

    Rationale: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  impact 1.0
  only_if('This control requires sudo permission to execute.') { bash('id').stdout =~ /uid\=0\(root\)/ }
  files = command('find /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf -type f').stdout.split
  files_with_correct_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*enforce_for_root\b/) }
  describe 'Ensure password quality is enforced for the root user' do
    it { expect(files_with_correct_conf).not_to(be_empty) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.3.1_Ensure_password_history_remember_is_configured' do
  title 'Ensure password history remember is configured'
  desc  "
    The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords. The number of passwords remembered is set via the remember argument value in set for the pam_pwhistory module.

    *  remember=
    <N> - <N> is the number of old passwords to remember</N></N>

    Rationale: Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password.

    **Note:** These change only apply to accounts configured on the local system.
  "
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/(?i)^\s*password\s+[^#\n\r]+\s+pam_pwhistory\.so\s+([^#\n\r]+\s+)?remember=(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.3.2_Ensure_password_history_is_enforced_for_the_root_user' do
  title 'Ensure password history is enforced for the root user'
  desc  "
    If the pwhistoryenforce_for_root option is enabled, the module will enforce password history for the root user as well

    Rationale: Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password

    **Note:** These change only apply to accounts configured on the local system.
  "
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/(?i)^\s*password\s+[^#\n\r]+\s+pam_pwhistory\.so\s+([^#\n\r]+\s+)?enforce_for_root\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.3.3_Ensure_pam_pwhistory_includes_use_authtok' do
  title 'Ensure pam_pwhistory includes use_authtok'
  desc  "
    use_authtok - When password changing enforce the module to set the new password to the one provided by a previously stacked password module

    Rationale: use_authtok allows multiple pam modules to confirm a new password before it is accepted.
  "
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/(?i)^\s*password\s+[^#\n\r]+\s+pam_pwhistory\.so\s+([^#\n\r]+\s+)?use_authtok\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.4.1_Ensure_pam_unix_does_not_include_nullok' do
  title 'Ensure pam_unix does not include nullok'
  desc  "
    The nullok argument overrides the default action of pam_unix.so to not permit the user access to a service if their official password is blank.

    Rationale: Using a strong password is essential to helping protect personal and sensitive information from unauthorized access
  "
  impact 1.0
  files = command('find /etc/pam.d/common-{password,auth,account,session,session-noninteractive} -type f').stdout.split
  files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ }
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*[^#\n\r]+\s+pam_unix\.so\s+([^#\n\r]+\s+)?nullok\b/) }
  describe 'Files in which nullok argument is set on pam_unix module' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.4.2_Ensure_pam_unix_does_not_include_remember' do
  title 'Ensure pam_unix does not include remember'
  desc  "
    The remember=n argument saves the last n passwords for each user in /etc/security/opasswd in order to force password change history and keep the user from alternating between the same password too frequently. The MD5 password hash algorithm is used for storing the old passwords. Instead of this option the pam_pwhistory module should be used. The pam_pwhistory module saves the last n passwords for each user in /etc/security/opasswd using the password hash algorithm set on the pam_unix module. This allows for the yescrypt or sha512 hash algorithm to be used.

    Rationale: The remember=n argument should be removed to ensure a strong password hashing algorithm is being used. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local user's old passwords stored in /etc/security/opasswd .
  "
  impact 1.0
  files = command('find /etc/pam.d/common-{password,auth,account,session,session-noninteractive} -type f').stdout.split
  files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ }
  files_with_wrong_conf = files.select { |file_path| file(file_path).content.match(/(?i)^\s*^\s*[^#\n\r]+\s+pam_unix\.so\s+([^#\n\r]+\s+)?remember=\d+\b/) }
  describe 'Files in which remember argument is set on pam_unix module' do
    it { expect(files_with_wrong_conf).to(be_empty) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.4.3_Ensure_pam_unix_includes_a_strong_password_hashing_algorithm' do
  title 'Ensure pam_unix includes a strong password hashing algorithm'
  desc  "
    A cryptographic hash function converts an arbitrary-length input into a fixed length output. Password hashing performs a one-way transformation of a password, turning the password into another string, called the hashed password.

    The pam_unix module can be configured to use one of the following hashing algorithms for user's passwords:

    * md5 - When a user changes their password next, encrypt it with the MD5 algorithm.
    * bigcrypt - When a user changes their password next, encrypt it with the DEC C2 algorithm.
    * sha256 - When a user changes their password next, encrypt it with the SHA256 algorithm. The SHA256 algorithm must be supported by the crypt(3) function.
    * sha512 - When a user changes their password next, encrypt it with the SHA512 algorithm. The SHA512 algorithm must be supported by the crypt(3) function.
    * blowfish - When a user changes their password next, encrypt it with the blowfish algorithm. The blowfish algorithm must be supported by the crypt(3) function.
    * gost_yescrypt - When a user changes their password next, encrypt it with the gost-yescrypt algorithm. The gost-yescrypt algorithm must be supported by the crypt(3) function.
    * yescrypt - When a user changes their password next, encrypt it with the yescrypt algorithm. The yescrypt algorithm must be supported by the crypt(3) function.

    Rationale: The SHA-512 and yescrypt algorithms provide a stronger hash than other algorithms used by Linux for password hash generation. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local user passwords.

    **Note:** These changes only apply to the local system.
  "
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/(?i)^\s*password\s+[^#\n\r]+\s+pam_unix\.so(\s+[^#\n\r]+)?\s+(sha512|yescrypt)\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.3.3.4.4_Ensure_pam_unix_includes_use_authtok' do
  title 'Ensure pam_unix includes use_authtok'
  desc  "
    use_authtok - When password changing enforce the module to set the new password to the one provided by a previously stacked password module

    Rationale: use_authtok allows multiple pam modules to confirm a new password before it is accepted.
  "
  impact 1.0
  describe file('/etc/pam.d/common-password') do
    its('content') { should match(/(?i)^\s*password\s+[^#\n\r]+\s+pam_unix\.so(\s+[^#\n\r]+)?\s+use_authtok\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.1.1_Ensure_password_expiration_is_configured' do
  title 'Ensure password expiration is configured'
  desc  "
    The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age.

    PASS_MAX_DAYS**
    <N>** - The maximum number of days a password may be used. If the password is older than this, a password change will be forced. If not specified, -1 will be assumed (which disables the restriction).</N>

    Rationale: The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity.

    We recommend a yearly password change. This is primarily because for all their good intentions users will share credentials across accounts. Therefore, even if a breach is publicly identified, the user may not see this notification, or forget they have an account on that site. This could leave a shared credential vulnerable indefinitely. Having an organizational policy of a 1-year (annual) password expiration is a reasonable compromise to mitigate this with minimal user burden.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp > 0 }
    its('PASS_MAX_DAYS') { should cmp <= 365 }
  end
  describe shadow.where { user =~ /^.+$/ && password =~ /^\$.+\$/ && (max_days.nil? || max_days.to_i > 365 || max_days.to_i <= 0) } do
    its('raw_data') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.1.3_Ensure_password_expiration_warning_days_is_configured' do
  title 'Ensure password expiration warning days is configured'
  desc  "
    The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days.

    PASS_WARN_AGE**
    <N>** - The number of days warning given before a password expires. A zero means warning is given only upon the day of expiration, a negative value means no warning is given. If not specified, no warning will be provided.</N>

    Rationale: Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe login_defs do
    its('PASS_WARN_AGE') { should cmp >= 7 }
  end
  describe shadow.where { user =~ /^.+$/ && password =~ /^\$.+\$/ && (warn_days.nil? || warn_days.to_i < 7) } do
    its('raw_data') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.1.4_Ensure_strong_password_hashing_algorithm_is_configured' do
  title 'Ensure strong password hashing algorithm is configured'
  desc  "
    A cryptographic hash function converts an arbitrary-length input into a fixed length output. Password hashing performs a one-way transformation of a password, turning the password into another string, called the hashed password.

    ENCRYPT_METHOD (string) - This defines the system default encryption algorithm for encrypting passwords (if no algorithm are specified on the command line). It can take one of these values:

    * MD5 - MD5-based algorithm will be used for encrypting password
    * SHA256 - SHA256-based algorithm will be used for encrypting password
    * SHA512 - SHA512-based algorithm will be used for encrypting password
    * BCRYPT - BCRYPT-based algorithm will be used for encrypting password
    * YESCRYPT - YESCRYPT-based algorithm will be used for encrypting password
    * DES - DES-based algorithm will be used for encrypting password (default)
    **Note:**

    *  This parameter overrides the deprecated MD5_CRYPT_ENAB variable.
    * This parameter will only affect the generation of group passwords.
    * The generation of user passwords is done by PAM and subject to the PAM configuration.
    * It is recommended to set this variable consistently with the PAM configuration.

    Rationale: The SHA-512 and yescrypt algorithms provide a stronger hash than other algorithms used by Linux for password hash generation. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local group passwords.
  "
  impact 1.0
  describe login_defs do
    its('ENCRYPT_METHOD') { should match(/(?i)\b(SHA512|YESCRYPT)\b/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.1.5_Ensure_inactive_password_lock_is_configured' do
  title 'Ensure inactive password lock is configured'
  desc  "
    User accounts that have been inactive for over a given period of time can be automatically disabled.

    INACTIVE - Defines the number of days after the password exceeded its maximum age where the user is expected to replace this password.

    The value is stored in the shadow password file. An input of 0 will disable an expired password with no delay. An input of -1 will blank the respective field in the shadow password file.

    Rationale: Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe file('/etc/default/useradd') do
    its('content') { should match(/(?i)^\s*INACTIVE\s*=\s*(4[0-5]|[1-3][0-9]|[1-9])\b/) }
  end
  describe shadow.where { user =~ /^.+$/ && password =~ /^\$.+\$/ && (inactive_days.nil? || inactive_days.to_i > 45 || inactive_days.to_i < 0) } do
    its('users') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.1.6_Ensure_all_users_last_password_change_date_is_in_the_past' do
  title 'Ensure all users last password change date is in the past'
  desc  "
    All users should have a password change date in the past.

    Rationale: If a user's recorded password change date is in the future, then they could bypass any set password expiration.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  today = DateTime.now.to_time.to_i / 86400
  describe shadow.where { user =~ /^.+$/ && password =~ /^\$.+\$/ && last_change.to_i > today } do
    its('users') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.1_Ensure_root_is_the_only_UID_0_account' do
  title 'Ensure root is the only UID 0 account'
  desc  "
    Any account with UID 0 has superuser privileges on the system.

    Rationale: This access must be limited to only the default root account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure access to the su command is restricted.
  "
  impact 1.0
  describe passwd.where { uid == '0' } do
    its('users') { should cmp ['root'] }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.2_Ensure_root_is_the_only_GID_0_account' do
  title 'Ensure root is the only GID 0 account'
  desc  "
    The usermod command can be used to specify which group the root account belongs to. This affects permissions of files that are created by the root account.

    Rationale: Using GID 0 for the root account helps prevent root -owned files from accidentally becoming accessible to non-privileged users.
  "
  impact 1.0
  describe passwd.where { user !~ /^(sync|shutdown|halt|operator)/ && gid == '0' } do
    its('users') { should cmp 'root' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.3_Ensure_group_root_is_the_only_GID_0_group' do
  title 'Ensure group root is the only GID 0 group'
  desc  "
    The groupmod command can be used to specify which group the root group belongs to. This affects permissions of files that are group owned by the root group.

    Rationale: Using GID 0 for the root group helps prevent root group owned files from accidentally becoming accessible to non-privileged users.
  "
  impact 1.0
  groups_with_gid_0 = etc_group.where(gid: '0').groups
  describe 'Ensure group root is the only GID 0 group' do
    it { expect(groups_with_gid_0).to(cmp == ['root']) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.4_Ensure_root_password_is_set' do
  title 'Ensure root password is set'
  desc  "
    There are a number of methods to access the root account directly. Without a password set any user would be able to gain access and thus control over the entire system.

    Rationale: Access to root should be secured at all times.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe shadow.where { user == 'root' and password !~ /^\$.+\$/ } do
    its('raw_data') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.5_Ensure_root_path_integrity' do
  title 'Ensure root path integrity'
  desc  "
    The root user can execute any command on the system and could be fooled into executing programs unintentionally if the PATH is not set correctly.

    Rationale: Including the current working directory (.) or other writable directory in root 's executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  root_path = command("sudo -Hiu root env | grep '^PATH=' | cut -d= -f2 | tr -d \"\n\"").stdout.to_s.split(':')
  describe root_path do
    it { should_not be_empty }
  end
  root_path.each do |path|
    describe path do
      it { should_not cmp '' }
      it { should_not cmp '.' }
    end
    describe directory(path) do
      it { should exist }
      it { should be_directory }
      it { should_not be_more_permissive_than('0755') }
      it { should be_owned_by 'root' }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.6_Ensure_root_user_umask_is_configured' do
  title 'Ensure root user umask is configured'
  desc  "
    The user file-creation mode mask ( umask ) is used to determine the file permission for newly created directories and files. In Linux, the default permissions for any newly created directory is 0777 ( rwxrwxrwx ), and for any newly created file it is 0666 ( rw-rw-rw- ). The umask modifies the default Linux permissions by restricting (masking) these permissions. The umask is not simply subtracted, but is processed bitwise. Bits set in the umask are cleared in the resulting file mode.

    umask can be set with either Octal or Symbolic values:

    * Octal (Numeric) Value - Represented by either three or four digits. ie umask 0027 or umask 027 .  If a four digit umask is used, the first digit is ignored. The remaining three digits effect the resulting permissions for user, group, and world/other respectively.
    * Symbolic Value - Represented by a comma separated list for User u , group g , and world/other o .  The permissions listed are not masked by umask . ie a umask set by umask u=rwx,g=rx,o= is the Symbolic equivalent of the Octalumask 027 .  This umask would set a newly created directory with file mode drwxr-x--- and a newly created file with file mode rw-r----- .
    **root user Shell Configuration Files:**

    * /root/.bash_profile - Is executed to configure the root users' shell before the initial command prompt. **Is only read by login shells.**
    * /root/.bashrc - Is executed for interactive shells. **only read by a shell that's both interactive and non-login**
    umask is set by order of precedence. If umask is set in multiple locations, this order of precedence will determine the system's default umask .

    **Order of precedence:**

    * /root/.bash_profile
    * /root/.bashrc
    * The system default umask

    Rationale: Setting a secure value for umask ensures that users make a conscious choice about their file permissions. A permissive umask value could result in directories or files with excessive permissions that can be read and/or written to by unauthorized users.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe file('/root/.bash_profile') do
    its('content') { should_not match(/(?i)^\s*umask\s+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))/) }
  end
  describe file('/root/.bashrc') do
    its('content') { should_not match(/(?i)^\s*umask\s+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.7_Ensure_system_accounts_do_not_have_a_valid_login_shell' do
  title 'Ensure system accounts do not have a valid login shell'
  desc  "
    There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell. Furthermore, a user may add special accounts that are not intended to provide an interactive shell.

    Rationale: It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the nologin shell. This prevents the account from potentially being used to run any commands.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  uid_min = login_defs.UID_MIN.to_i
  l_valid_shells = command("awk -F/ '/^\\// && $NF != \"nologin\" { print }' /etc/shells").stdout.split
  describe passwd.where { user !~ /^(root|halt|sync|shutdown|nfsnobody)$/ && (uid.to_i < uid_min || uid.to_i == 65534) && l_valid_shells.include?(shell) } do
    its('users') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.2.8_Ensure_accounts_without_a_valid_login_shell_are_locked' do
  title 'Ensure accounts without a valid login shell are locked'
  desc  "
    There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell. Furthermore, a user may add special accounts that are not intended to provide an interactive shell.

    Rationale: It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the nologin shell. This prevents the account from potentially being used to run any commands.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  valid_shells = command("awk -F/ '$NF != \"nologin\" {print}' /etc/shells | sed -rn '/^\\//p'").stdout.split
  passwd.where { user != 'root' && !valid_shells.include?(shell) }.users.each do |user|
    describe command("passwd -S #{user}") do
      its('stdout') { should match(/#{user}\s+(L|LK)/) }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.3.2_Ensure_default_user_shell_timeout_is_configured' do
  title 'Ensure default user shell timeout is configured'
  desc  "
    TMOUT is an environmental setting that determines the timeout of a shell in seconds.

    *  TMOUT= **n** - Sets the shell timeout to **n** seconds.  A setting of TMOUT=0 disables timeout.
    * readonly TMOUT- Sets the TMOUT environmental variable as readonly, preventing unwanted modification during run-time.
    * export TMOUT - exports the TMOUT variable
    **System Wide Shell Configuration Files:**

    * /etc/profile - used to set system wide environmental variables on users shells. The variables are sometimes the same ones that are in the .bash_profile , however this file is used to set an initial PATH or PS1 for all shell users of the system. ** is only executed for interactive **login** shells, or shells executed with the --login parameter. **
    * /etc/profile.d - /etc/profile will execute the scripts within /etc/profile.d/*.sh . It is recommended to place your configuration in a shell script within /etc/profile.d to set your own system wide environmental variables.
    * /etc/bashrc - System wide version of .bashrc .  In Fedora derived distributions, /etc/bashrc also invokes /etc/profile.d/*.sh if **non-login** shell, but redirects output to /dev/null if **non-interactive.**** Is only executed for **interactive** shells or if BASH_ENV is set to /etc/bashrc . **

    Rationale: Setting a timeout value reduces the window of opportunity for unauthorized user access to another user's shell session that has been left unattended. It also ends the inactive session and releases the resources associated with that session.
  "
  impact 1.0
  files = command('find /etc/bashrc /etc/profile /etc/profile.d/*.sh -type f').stdout.split
  files_with_tmout = files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b/ }
  describe 'Verify timeout parameter correctly configured or not' do
    it "#{files_with_tmout} is expected to not be empty" do
      expect(files_with_tmout).to_not(be_empty)
    end
  end
  describe command('grep -P \'^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b\' /etc/profile /etc/profile.d/*.sh /etc/bashrc') do
    its('stdout') { should be_empty }
  end
  files_with_tmout_and_readonly = files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b/ }
  describe 'Verify readonly_timeout parameter correctly configured or not' do
    it "#{files_with_tmout_and_readonly} is expected to not be empty" do
      expect(files_with_tmout_and_readonly).to_not(be_empty)
    end
  end
  files_with_tmout_and_export = files.reject { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b/ }
  describe 'Verify export_timeout parameter correctly configured or not' do
    it "#{files_with_tmout_and_export} is expected to not be empty" do
      expect(files_with_tmout_and_export).to_not(be_empty)
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_5.4.3.3_Ensure_default_user_umask_is_configured' do
  title 'Ensure default user umask is configured'
  desc  "
    The user file-creation mode mask ( umask ) is used to determine the file permission for newly created directories and files. In Linux, the default permissions for any newly created directory is 0777 ( rwxrwxrwx ), and for any newly created file it is 0666 ( rw-rw-rw- ). The umask modifies the default Linux permissions by restricting (masking) these permissions. The umask is not simply subtracted, but is processed bitwise. Bits set in the umask are cleared in the resulting file mode.

    umask can be set with either Octal or Symbolic values:

    * Octal (Numeric) Value - Represented by either three or four digits. ie umask 0027 or umask 027 .  If a four digit umask is used, the first digit is ignored. The remaining three digits effect the resulting permissions for user, group, and world/other respectively.
    * Symbolic Value - Represented by a comma separated list for User u , group g , and world/other o .  The permissions listed are not masked by umask . ie a umask set by umask u=rwx,g=rx,o= is the Symbolic equivalent of the Octalumask 027 .  This umask would set a newly created directory with file mode drwxr-x--- and a newly created file with file mode rw-r----- .
    The default umask can be set to use the pam_umask module or in a System Wide Shell Configuration File . The user creating the directories or files has the discretion of changing the permissions via the chmod command, or choosing a different default umask by adding the umask command into a User Shell Configuration File , ( .bash_profile or .bashrc ), in their home directory.

    **Setting the default umask:**

    *  pam_umask module: *  will set the umask according to the system default in /etc/login.defs and user settings, solving the problem of different umask settings with different shells, display managers, remote sessions etc.
    * umask=
    <mask> value in the /etc/login.defs file is interpreted as Octal
    *  Setting USERGROUPS_ENAB to yes in /etc/login.defs (default): *  will enable setting of the umask group bits to be the same as owner bits. (examples: 022 -&gt; 002, 077 -&gt; 007) for non-root users, if the uid is the same as gid , and username is the same as the <primary/>name&gt;
    * userdel will remove the user's group if it contains no more members, and useradd will create by default a group with the name of the user
    * System Wide Shell Configuration File : * /etc/profile - used to set system wide environmental variables on users shells. The variables are sometimes the same ones that are in the .bash_profile , however this file is used to set an initial PATH or PS1 for all shell users of the system. ** is only executed for interactive **login** shells, or shells executed with the --login parameter. **
    * /etc/profile.d - /etc/profile will execute the scripts within /etc/profile.d/*.sh . It is recommended to place your configuration in a shell script within /etc/profile.d to set your own system wide environmental variables.
    * /etc/bashrc - System wide version of .bashrc .  In Fedora derived distributions, etc/bashrc also invokes /etc/profile.d/*.sh if **non-login** shell, but redirects output to /dev/null if **non-interactive.**** Is only executed for **interactive** shells or if BASH_ENV is set to /etc/bashrc . **
    **User Shell Configuration Files:**

    * ~/.bash_profile - Is executed to configure your shell before the initial command prompt. **Is only read by login shells.**
    * ~/.bashrc - Is executed for interactive shells. **only read by a shell that's both interactive and non-login**
    umask is set by order of precedence. If umask is set in multiple locations, this order of precedence will determine the system's default umask .

    **Order of precedence:**

    *  A file in /etc/profile.d/ ending in .sh - This will override any other system-wide umask setting
    *  In the file /etc/profile
    *  On the pam_umask.so module in /etc/pam.d/postlogin
    *  In the file /etc/login.defs
    *  In the file /etc/default/login</mask>

    Rationale: Setting a secure default value for umask ensures that users make a conscious choice about their file permissions. A permissive umask value could result in directories or files with excessive permissions that can be read and/or written to by unauthorized users.
  "
  impact 1.0
  describe bash('#!/usr/bin/env bash
    {
        l_output="" l_output2=""
        file_umask_chk()
        {
          if grep -Psiq -- \'^\h*umask\h+(0?[0-7][2-7]7|u(=[rwx]{0,3}),g=([rx]{0,2}),o=)(\h*#.*)?$\' "$l_file"; then
              l_output="$l_output\n - umask is set correctly in \"$l_file\""
          elif grep -Psiq -- \'^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))\' "$l_file"; then
              l_output2="$l_output2\n - umask is incorrectly set in \"$l_file\""
          fi
        }
        while IFS= read -r -d $\'\0\' l_file; do
          file_umask_chk
        done < <(find /etc/profile.d/ -type f -name \'*.sh\' -print0)
        [ -z "$l_output" ] && l_file="/etc/profile" && file_umask_chk
        [ -z "$l_output" ] && l_file="/etc/bashrc" && file_umask_chk
        [ -z "$l_output" ] && l_file="/etc/bash.bashrc" && file_umask_chk
        [ -z "$l_output" ] && l_file="/etc/pam.d/postlogin"
        if [ -z "$l_output" ]; then
          if grep -Psiq -- \'^\h*session\h+[^#\n\r]+\h+pam_umask\.so\h+([^#\n\r]+\h+)?umask=(0?[0-7][2-7]7)\b\' "$l_file"; then
              l_output1="$l_output1\n - umask is set correctly in \"$l_file\""
          elif grep -Psiq \'^\h*session\h+[^#\n\r]+\h+pam_umask\.so\h+([^#\n\r]+\h+)?umask=(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b))\' "$l_file"; then
              l_output2="$l_output2\n - umask is incorrectly set in \"$l_file\""
          fi
        fi
        [ -z "$l_output" ] && l_file="/etc/login.defs" && file_umask_chk
        [ -z "$l_output" ] && l_file="/etc/default/login" && file_umask_chk
        [[ -z "$l_output" && -z "$l_output2" ]] && l_output2="$l_output2\n - umask is not set"
        if [ -z "$l_output2" ]; then
          echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
        else
          echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
          [ -n "$l_output" ] && echo -e "\n- * Correctly configured * :\n$l_output\n"
        fi
    }').stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.1.1_Ensure_AIDE_is_installed' do
  title 'Ensure AIDE is installed'
  desc  "
    AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.

    Rationale: By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries.
  "
  impact 1.0
  describe package('aide') do
    it { should be_installed }
  end
  describe package('aide-common') do
    it { should be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.1.2_Ensure_filesystem_integrity_is_regularly_checked' do
  title 'Ensure filesystem integrity is regularly checked'
  desc  "
    Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.

    Rationale: Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion.
  "
  impact 1.0
  if service('aidecheck.service').enabled? && service('aidecheck.timer').enabled?
    describe service('aidecheck.service') do
      it { should be_enabled }
    end
    describe service('aidecheck.timer') do
      it { should be_enabled }
      it { should be_running }
    end
    files = command('find /etc/systemd/system/ -type f -regex .\\*/aidecheck.service').stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ %r{^\s*ExecStart=([^#]+\s+)?/usr/bin/aide\.wrapper\s--config\s/etc/aide/aide\.conf\s--(check|update)\b.*$} } do
      it { should_not be_empty }
    end
    files = command('find /etc/systemd/system/ -type f -regex .\\*/aidecheck.timer').stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\s*Unit=aidecheck\.service\s*(\s+#.*)?$/ } do
      it { should_not be_empty }
    end
  else
    cron_files = ['/etc/crontab', '/var/spool/cron/tabs/root'] + command('find /var/spool/cron/* -type f').stdout.split + command('find /etc/cron.d/* -type f').stdout.split + command('find /etc/cron.hourly/* -type f').stdout.split + command('find /etc/cron.daily/* -type f').stdout.split + command('find /etc/cron.weekly/* -type f').stdout.split + command('find /etc/cron.monthly/* -type f').stdout.split
    describe.one do
      cron_files.each do |cron_file|
        describe file(cron_file) do
          its('content') { should match(%r{^([-0-9*/,A-Za-z]+\s+){5}([^#]+\s+)?/usr/bin/aide\.wrapper\s--config\s+/etc/aide/aide\.conf\s--check\b.*$}) }
        end
        next unless cron_file.include?('/etc/cron.daily')
        describe file(cron_file) do
          its('content') { should match(%r{^([^#\n\r]+\h+)?(/usr/s?bin/|^\h*)aide(\.wrapper)?\h+(--check|([^#\n\r]+\h+)?\$AIDEARGS)\b}) }
        end
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.1.1_Ensure_journald_service_is_enabled_and_active' do
  title 'Ensure journald service is enabled and active'
  desc  "
    Ensure that the systemd-journald service is enabled to allow capturing of logging events.

    Rationale: If the systemd-journald service is not enabled to start on boot, the system will not capture logging events.
  "
  impact 1.0
  describe service('systemd-journald').params.UnitFileState do
    it { should eq 'static' }
  end
  describe service('systemd-journald').params.ActiveState do
    it { should eq 'active' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.1.2_Ensure_journald_log_file_access_is_configured' do
  title 'Ensure journald log file access is configured'
  desc  "
    Journald will create logfiles that do not already exist on the system. This setting controls what permissions will be applied to these newly created files.

    Rationale: It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.
  "
  impact 0.0
  describe 'This recommendation cannot be checked automatically.' do
    skip('This recommendation requires manual review:
      First determine if there is an override file /etc/tmpfiles.d/systemd.conf. If so, this file will override all default settings as defined in /usr/lib/tmpfiles.d/systemd.conf and should be inspected.

      If no override file exists, inspect the default /usr/lib/tmpfiles.d/systemd.conf against the site specific requirements.

      Ensure that file permissions are mode 0640 or more restrictive.
    ')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.1.3_Ensure_journald_log_file_rotation_is_configured' do
  title 'Ensure journald log file rotation is configured'
  desc  "
    Journald includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageably large. The file /etc/systemd/journald.conf is the configuration file used to specify how logs generated by Journald should be rotated.

    Rationale: By keeping the log files smaller and more manageable, a system administrator can easily archive these files to another system and spend less time looking through inordinately large log files.
  "
  impact 0.0
  describe 'This recommendation cannot be checked automatically.' do
    skip('This recommendation requires manual review:
      Review /etc/systemd/journald.conf and files in the /etc/systemd/journald.conf.d/ directory ending in .conf. Verify logs are rotated according to site policy. The specific parameters for log rotation are:

      SystemMaxUse=
      SystemKeepFree=
      RuntimeMaxUse=
      RuntimeKeepFree=
      MaxFileSec=
    ')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.1.4_Ensure_journald_ForwardToSyslog_is_disabled' do
  title 'Ensure journald ForwardToSyslog is disabled'
  desc  "
    Data from journald should be kept in the confines of the service and not forwarded to other services.

    Rationale: Logs of the system should be handled by journald and not forwarded to other logging mechanisms.
  "
  impact 1.0
  describe bash('#!/usr/bin/env bash

    {
      l_output="" l_output2=""
      a_parlist=("ForwardToSyslog=yes")
      l_systemd_config_file="/etc/systemd/journald.conf" # Main systemd configuration file
      config_file_parameter_chk()
      {
          unset A_out; declare -A A_out # Check config file(s) setting
          while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                  l_file="${l_out//# /}"
                else
                  l_systemd_parameter="$(awk -F= \'{print $1}\' <<< "$l_out" | xargs)"
                  grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file")
                fi
            fi
          done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep -Pio \'^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)\')
          if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
                l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
                l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}"
                if ! grep -Piq "^\h*$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then
                  l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf \'%s\' "${A_out[@]}")\"\n"
                else
                  l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf \'%s\' "${A_out[@]}")\"\n"
                fi
            done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
          else
            l_output="$l_output\n - \"$l_systemd_parameter_name\" is not set in an included file\n   ** Note: \"$l_systemd_parameter_name\" May be set in a file that\'s ignored by load procedure **\n"
          fi
      }
      while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
          l_systemd_parameter_name="${l_systemd_parameter_name// /}"
          l_systemd_parameter_value="${l_systemd_parameter_value// /}"
          config_file_parameter_chk
      done < <(printf \'%s\n\' "${a_parlist[@]}")
      if [ -z "$l_output2" ]; then # Provide output from checks
          echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      else
          echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
          [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      fi
    }').stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.1.5_Ensure_journald_Storage_is_configured' do
  title 'Ensure journald Storage is configured'
  desc  "
    Data from journald may be stored in volatile memory or persisted locally on the server.  Logs in memory will be lost upon a system reboot.  By persisting logs to local disk on the server they are protected from loss due to a reboot.

    Rationale: Writing log data to disk will provide the ability to forensically reconstruct events which may have impacted the operations or security of a system even after a system crash or reboot.
  "
  impact 1.0
  describe bash('#!/usr/bin/env bash

    {
      l_output="" l_output2=""
      a_parlist=("Storage=persistent")
      l_systemd_config_file="/etc/systemd/journald.conf" # Main systemd configuration file
      config_file_parameter_chk()
      {
          unset A_out; declare -A A_out # Check config file(s) setting
          while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                  l_file="${l_out//# /}"
                else
                  l_systemd_parameter="$(awk -F= \'{print $1}\' <<< "$l_out" | xargs)"
                  grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file")
                fi
            fi
          done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep -Pio \'^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)\')
          if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
                l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
                l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}"
                if grep -Piq "^\h*$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then
                  l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf \'%s\' "${A_out[@]}")\"\n"
                else
                  l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf \'%s\' "${A_out[@]}")\" and should have a value matching: \"$l_systemd_parameter_value\"\n"
                fi
            done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
          else
            l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is not set in an included file\n   ** Note: \"$l_systemd_parameter_name\" May be set in a file that\'s ignored by load procedure **\n"
          fi
      }
      while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
          l_systemd_parameter_name="${l_systemd_parameter_name// /}"
          l_systemd_parameter_value="${l_systemd_parameter_value// /}"
          config_file_parameter_chk
      done < <(printf \'%s\n\' "${a_parlist[@]}")
      if [ -z "$l_output2" ]; then # Provide output from checks
          echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      else
          echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2"
          [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      fi
    }').stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.1.6_Ensure_journald_Compress_is_configured' do
  title 'Ensure journald Compress is configured'
  desc  "
    The journald system includes the capability of compressing overly large files to avoid filling up the system with logs or making the logs unmanageably large.

    Rationale: Uncompressed large files may unexpectedly fill a filesystem leading to resource unavailability.  Compressing logs prior to write can prevent sudden, unexpected filesystem impacts.
  "
  impact 1.0
  describe bash('#!/usr/bin/env bash

    {
      l_output="" l_output2=""
      a_parlist=("Compress=yes")
      l_systemd_config_file="/etc/systemd/journald.conf" # Main systemd configuration file
      config_file_parameter_chk()
      {
          unset A_out; declare -A A_out # Check config file(s) setting
          while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                  l_file="${l_out//# /}"
                else
                  l_systemd_parameter="$(awk -F= \'{print $1}\' <<< "$l_out" | xargs)"
                  grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file")
                fi
            fi
          done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep -Pio \'^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)\')
          if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
                l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
                l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}"
                if grep -Piq "^\h*$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then
                  l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf \'%s\' "${A_out[@]}")\"\n"
                else
                  l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf \'%s\' "${A_out[@]}")\" and should have a value matching: \"$l_systemd_parameter_value\"\n"
                fi
            done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
          else
            l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is not set in an included file\n   ** Note: \"$l_systemd_parameter_name\" May be set in a file that\'s ignored by load procedure **\n"
          fi
      }
      while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
          l_systemd_parameter_name="${l_systemd_parameter_name// /}"
          l_systemd_parameter_value="${l_systemd_parameter_value// /}"
          config_file_parameter_chk
      done < <(printf \'%s\n\' "${a_parlist[@]}")
      if [ -z "$l_output2" ]; then # Provide output from checks
          echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      else
          echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2"
          [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      fi
    }').stdout do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.2.1_Ensure_systemd-journal-remote_is_installed' do
  title 'Ensure systemd-journal-remote is installed'
  desc  "
    Journald systemd-journal-remote supports the ability to send log events it gathers to a remote log host or to receive messages from remote hosts, thus enabling centralized log management.

    Rationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.
  "
  impact 1.0
  only_if('This recommendation applies only if journald is the preferred method for capturing logs.') { log_capturing_method == 'journald' }
  describe package('systemd-journal-remote') do
    it { should be_installed }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.2.2_Ensure_systemd-journal-remote_authentication_is_configured' do
  title 'Ensure systemd-journal-remote authentication is configured'
  desc  "
    Journald systemd-journal-upload supports the ability to send log events it gathers to a remote log host.

    Rationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.
  "
  impact 0.0
  only_if('This recommendation applies only if journald is the preferred method for capturing logs.') { log_capturing_method == 'journald' }
  describe 'This recommendation cannot be checked automatically' do
    skip('This recommendation requires manual review - Ensure systemd-journal-remote authentication is configured
    Run the following command to verify systemd-journal-upload authentication is configured:

    # grep -P "^ *URL=|^ *ServerKeyFile=|^ *ServerCertificateFile=|^ *TrustedCertificateFile=" /etc/systemd/journal-upload.conf
    Verify the output matches per your environments certificate locations and the URL of the log server:

    Example:

    [Upload]
    URL=192.168.50.42
    ServerKeyFile=/etc/ssl/private/journal-upload.pem
    ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
    TrustedCertificateFile=/etc/ssl/ca/trusted.pem')
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.2.3_Ensure_systemd-journal-upload_is_enabled_and_active' do
  title 'Ensure systemd-journal-upload is enabled and active'
  desc  "
    Journald systemd-journal-upload supports the ability to send log events it gathers to a remote log host.

    Rationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.
  "
  impact 1.0
  only_if('This recommendation applies only if journald is the preferred method for capturing logs.') { log_capturing_method == 'journald' }
  describe service('systemd-journal-upload') do
    it { should be_enabled }
    its('params.ActiveState') { should eq 'active' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.1.2.4_Ensure_systemd-journal-remote_service_is_not_in_use' do
  title 'Ensure systemd-journal-remote service is not in use'
  desc  "
    Journald systemd-journal-remote supports the ability to receive messages from remote hosts, thus acting as a log server. Clients should not receive data from other hosts.

    **NOTE:**

    *  The same package, systemd-journal-remote , is used for both sending logs to remote hosts and receiving incoming logs.
    *  With regards to receiving logs, there are two services; systemd-journal-remote.socket and systemd-journal-remote.service .

    Rationale: If a client is configured to also receive data, thus turning it into a server, the client system is acting outside it's operational boundary.
  "
  impact 1.0
  only_if('This recommendation applies only if journald is the preferred method for capturing logs.') { log_capturing_method == 'journald' }
  describe service('systemd-journal-remote.socket') do
    it { should_not be_enabled }
    its('params.ActiveState') { should_not eq 'active' }
  end
  describe service('systemd-journal-remote.service') do
    it { should_not be_enabled }
    its('params.ActiveState') { should_not eq 'active' }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_6.2.2.1_Ensure_access_to_all_logfiles_has_been_configured' do
  title 'Ensure access to all logfiles has been configured'
  desc  "
    Log files contain information from many services on the the local system, or in the event of a centralized log server, others systems logs as well.

    In general log files are found in /var/log/ , although application can be configured to store logs elsewhere. Should your application store logs in another, ensure to run the same test on that location.

    Rationale: It is important that log files have the correct permissions to ensure that sensitive data is protected and that only the appropriate users / groups have access to them.
  "
  impact 1.0
  var_log_files = command('find /var/log -type f').stdout.strip.split("\n")
  var_log_files.each do |file_path|
    file_name = file_path.split('/')[-1]
    case file_name
    when /(lastlog|lastlog.*|wtmp|wtmp.*|wtmp-*|btmp|btmp.*|btmp-*|README)/
      describe file(file_path.to_s) do
        it { should exist }
        its('owner') { should match(/root/) }
        its('group') { should match(/\s*(root|utmp)\s*$/) }
        it { should_not be_more_permissive_than('0664') }
      end
    when /(secure|auth.log|syslog|messages)/
      describe file(file_path.to_s) do
        it { should exist }
        its('owner') { should match(/(syslog|root)/) }
        its('group') { should match(/\s*(adm|root)\s*$/) }
        it { should_not be_more_permissive_than('0640') }
      end
    when /(SSSD|sssd)/
      describe file(file_path.to_s) do
        it { should exist }
        its('owner') { should match(/SSSD|root/) }
        its('group') { should match(/\s*(SSSD|root)\s*$/) }
        it { should_not be_more_permissive_than('0660') }
      end
    when /(gdm|gdm3)/
      describe file(file_path.to_s) do
        it { should exist }
        its('owner') { should match(/root/) }
        its('group') { should match(/\s*(root|gdm|gdm3)\s*$/) }
        it { should_not be_more_permissive_than('0660') }
      end
    when /(journal)/
      describe file(file_path.to_s) do
        it { should exist }
        its('owner') { should match(/root/) }
        its('group') { should match(/\s*(systemd-journal|root)\s*$/) }
        it { should_not be_more_permissive_than('0640') }
      end
    else
      describe file(file_path.to_s) do
        it { should exist }
        its('owner') { should match(/syslog|root/) }
        its('group') { should match(/\s*(adm|root)\s*$/) }
        it { should_not be_more_permissive_than('0640') }
      end
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.1_Ensure_permissions_on_etcpasswd_are_configured' do
  title 'Ensure permissions on /etc/passwd are configured'
  desc  "
    The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.

    Rationale: It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file('/etc/passwd') do
    it { should exist }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
    it { should_not be_more_permissive_than('644') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.2_Ensure_permissions_on_etcpasswd-_are_configured' do
  title 'Ensure permissions on /etc/passwd- are configured'
  desc  "
    The /etc/passwd- file contains backup user account information.

    Rationale: It is critical to ensure that the /etc/passwd- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file('/etc/passwd-') do
    it { should exist }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
    it { should_not be_more_permissive_than('644') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.3_Ensure_permissions_on_etcgroup_are_configured' do
  title 'Ensure permissions on /etc/group are configured'
  desc  "
    The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.

    Rationale: The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  impact 1.0
  describe file('/etc/group') do
    it { should exist }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
    it { should_not be_more_permissive_than('644') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.4_Ensure_permissions_on_etcgroup-_are_configured' do
  title 'Ensure permissions on /etc/group- are configured'
  desc  "
    The /etc/group- file contains a backup list of all the valid groups defined in the system.

    Rationale: It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file('/etc/group-') do
    it { should exist }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
    it { should_not be_more_permissive_than('644') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.5_Ensure_permissions_on_etcshadow_are_configured' do
  title 'Ensure permissions on /etc/shadow are configured'
  desc  "
    The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.

    Rationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts.
  "
  impact 1.0
  describe file('/etc/shadow') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should be_in %w(root shadow) }
    it { should_not be_more_permissive_than('0640') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.6_Ensure_permissions_on_etcshadow-_are_configured' do
  title 'Ensure permissions on /etc/shadow- are configured'
  desc  "
    The /etc/shadow- file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.

    Rationale: It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file('/etc/shadow-') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should be_in %w(root shadow) }
    it { should_not be_more_permissive_than('0640') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.7_Ensure_permissions_on_etcgshadow_are_configured' do
  title 'Ensure permissions on /etc/gshadow are configured'
  desc  "
    The /etc/gshadow file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.

    Rationale: If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as group administrators) could also be useful to subvert the group.
  "
  impact 1.0
  describe file('/etc/gshadow') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should be_in %w(root shadow) }
    it { should_not be_more_permissive_than('0640') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.8_Ensure_permissions_on_etcgshadow-_are_configured' do
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc  "
    The /etc/gshadow- file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.

    Rationale: It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file('/etc/gshadow-') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should be_in %w(root shadow) }
    it { should_not be_more_permissive_than('0640') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.9_Ensure_permissions_on_etcshells_are_configured' do
  title 'Ensure permissions on /etc/shells are configured'
  desc  "
    /etc/shells is a text file which contains the full pathnames of valid login shells. This file is consulted by chsh and available to be queried by other programs.

    Rationale: It is critical to ensure that the /etc/shells file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe file('/etc/shells') do
    it { should exist }
    its('uid') { should cmp 0 }
    its('gid') { should cmp 0 }
    it { should_not be_more_permissive_than('0644') }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.10_Ensure_permissions_on_etcsecurityopasswd_are_configured' do
  title 'Ensure permissions on /etc/security/opasswd are configured'
  desc  "
    /etc/security/opasswd and it's backup /etc/security/opasswd.old hold user's previous passwords if pam_unix or pam_pwhistory is in use on the system

    Rationale: It is critical to ensure that /etc/security/opasswd is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  impact 1.0
  describe.one do
    describe file('/etc/security/opasswd') do
      it { should_not exist }
    end
    describe file('/etc/security/opasswd') do
      it { should exist }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
      it { should_not be_more_permissive_than('0600') }
    end
  end
  describe.one do
    describe file('/etc/security/opasswd.old') do
      it { should_not exist }
    end
    describe file('/etc/security/opasswd.old') do
      it { should exist }
      its('uid') { should cmp 0 }
      its('gid') { should cmp 0 }
      it { should_not be_more_permissive_than('0600') }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.11_Ensure_world_writable_files_and_directories_are_secured' do
  title 'Ensure world writable files and directories are secured'
  desc  "
    World writable files are the least secure. Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity. See the chmod(2) man page for more information.

    Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.

    Rationale: Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity.

    This feature prevents the ability to delete or rename files in world writable directories (such as /tmp ) that are owned by another user.
  "
  impact 1.0
  describe bash("#!/usr/bin/env bash
    l_output=\"\" l_output2=\"\"
    l_limit=\"50\" # Set report output limit
    l_smask='01000'
    # Initialize arrays
    a_path=()
    a_arr=()
    a_file=()
    a_dir=()

    # Populate array with excluded directories
    a_path=(! -path \"/run/user/*\" -a ! -path \"/proc/*\" -a ! -path \"*/containerd/*\" -a ! -path \"*/kubelet/pods/*\" -a ! -path \"/sys/kernel/security/apparmor/*\" -a ! -path \"/snap/*\" -a ! -path \"/sys/fs/cgroup/memory/*\")
    while read -r l_bfs; do
      a_path+=( -a ! -path \"\"$l_bfs\"/*\")
    done < <(findmnt -Dkerno fstype,target | awk '$1 ~ /^\\s*(nfs|proc|smb)/ {print $2}')

    # Populate array with files that will possibly fail one of the audits
    while IFS= read -r -d $'\\0' l_file; do
      [ -e \"$l_file\" ] && a_arr+=(\"$(stat -Lc '%n^%#a' \"$l_file\")\")
    done < <(find / \\( \"${a_path[@]}\" \\) \\( -type f -o -type d \\) -perm -0002 -print0 2>/dev/null)
    while IFS=\"^\" read -r l_fname l_mode; do
      [ -f \"$l_fname\" ] && a_file+=(\"$l_fname\") # Add WR files
      if [ -d \"$l_fname\" ]; then # Add directories w/o sticky bit
        [ ! $(( $l_mode & $l_smask )) -gt 0 ] && a_dir+=(\"$l_fname\")
      fi
    done < <(printf '%s\\n' \"${a_arr[@]}\")

    # Generate output reports
    if ! (( ${#a_file[@]} > 0 )); then
      l_output=\"$l_output\\n  - No world writable files exist on the local filesystem.\"
    else
      l_output2=\"$l_output2\\n - There are \\\"$(printf '%s' \"${#a_file[@]}\")\\\" World writable files on the system.\\n   - The following is a list of World writable files:\\n$(printf '%s\\n' \"${a_file[@]:0:$l_limit}\")\\n   - end of list\\n\"
    fi
    if ! (( ${#a_dir[@]} > 0 )); then
      l_output=\"$l_output\\n  - Sticky bit is set on world writable directories on the local filesystem.\"
    else
      l_output2=\"$l_output2\\n - There are \\\"$(printf '%s' \"${#a_dir[@]}\")\\\" World writable directories without the sticky bit on the system.\\n   - The following is a list of World writable directories without the sticky bit:\\n$(printf '%s\\n' \"${a_dir[@]:0:$l_limit}\")\\n   - end of list\\n\"
    fi
    if (( ${#a_file[@]} > \"$l_limit\" )) || (( ${#a_dir[@]} > \"$l_limit\" )); then
      l_output2=\"\\n    ** NOTE: **\\n    More than \\\"$l_limit\\\" world writable files and/or \\n    World writable directories without the sticky bit exist\\n    only the first \\\"$l_limit\\\" will be listed\\n$l_output2\"
    fi

    # Remove arrays
    unset a_path
    unset a_arr
    unset a_file
    unset a_dir
    # If l_output2 is empty, we pass
    if [ -z \"$l_output2\" ]; then
      echo -e \"\\n- Audit Result:\\n  ** PASS **\\n - * Correctly configured * :\\n$l_output\\n\"
      exit 0
    else
      echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - * Reasons for audit failure * :\\n$l_output2\"
      [ -n \"$l_output\" ] && echo -e \"- * Correctly configured * :\\n$l_output\\n\"
      exit 1
    fi").stdout do
    it { should match(/PASS/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.12_Ensure_no_files_or_directories_without_an_owner_and_a_group_exist' do
  title 'Ensure no files or directories without an owner and a group exist'
  desc  "
    Administrators may delete users or groups from the system and neglect to remove all files and/or directories owned by those users or groups.

    Rationale: A new user or group who is assigned a deleted user's user ID or group ID may then end up \"owning\" a deleted user or group's files, and thus have more access on the system than was intended.
  "
  impact 1.0
  describe bash("#!/usr/bin/env bash
    l_output=\"\" l_output2=\"\"
    l_limit=\"50\" # Set report output limit
    # Initialize arrays
    a_path=()
    a_arr=()
    a_nouser=()
    a_nogroup=()

    # Populate array with paths to be excluded
    a_path=(! -path \"/run/user/*\" -a ! -path \"/proc/*\" -a ! -path \"*/containerd/*\" -a ! -path \"*/kubelet/pods/*\")
    while read -r l_bfs; do
      a_path+=( -a ! -path \"\"$l_bfs\"/*\")
    done < <(findmnt -Dkerno fstype,target | awk '$1 ~ /^\\s*(nfs|proc|smb)/ {print $2}')

    # Populate array with files that will possibly fail one of the audits
    while IFS= read -r -d $'\\0' l_file; do
      [ -e \"$l_file\" ] && a_arr+=(\"$(stat -Lc '%n^%U^%G' \"$l_file\")\") && echo \"Adding: $l_file\"
    done < <(find / \\( \"${a_path[@]}\" \\) \\( -type f -o -type d \\) \\( -nouser -o -nogroup \\) -print0 2> /dev/null)

    # Test files in the array a_arr
    while IFS=\"^\" read -r l_fname l_user l_group; do
      [ \"$l_user\" = \"UNKNOWN\" ] && a_nouser+=(\"$l_fname\")
      [ \"$l_group\" = \"UNKNOWN\" ] && a_nogroup+=(\"$l_fname\")
    done <<< \"$(printf '%s\\n' \"${a_arr[@]}\")\"

    if ! (( ${#a_nouser[@]} > 0 )); then
      l_output=\"$l_output\\n  - No unowned files or directories exist on the local filesystem.\"
    else
      l_output2=\"$l_output2\\n  - There are \\\"$(printf '%s' \"${#a_nouser[@]}\")\\\" unowned files or directories on the system.\\n   - The following is a list of unowned files and/or directories:\\n$(printf '%s\\n' \"${a_nouser[@]:0:$l_limit}\")\\n   - end of list\"
    fi
    if ! (( ${#a_nogroup[@]} > 0 )); then
      l_output=\"$l_output\\n  - No ungrouped files or directories exist on the local filesystem.\"
    else
      l_output2=\"$l_output2\\n  - There are \\\"$(printf '%s' \"${#a_nogroup[@]}\")\\\" ungrouped files or directories on the system.\\n   - The following is a list of ungrouped files and/or directories:\\n$(printf '%s\\n' \"${a_nogroup[@]:0:$l_limit}\")\\n   - end of list\"
    fi
    if (( ${#a_nouser[@]} > \"$l_limit\" )) || (( ${#a_nogroup[@]} > \"$l_limit\" )); then
      l_output2=\"\\n  ** Note: more than \\\"$l_limit\\\" unowned and/or ungrouped files and/or directories have been found **\\n  ** only the first \\\"$l_limit\\\" will be listed **\\n$l_output2\"
    fi

    # Remove arrays
    unset a_path
    unset a_arr
    unset a_nouser
    unset a_nogroup
    # If l_output2 is empty, we pass
    if [ -z \"$l_output2\" ]; then
      echo -e \"\\n- Audit Result:\\n  ** PASS **\\n - * Correctly configured * :\\n$l_output\\n\"
      exit 0
    else
      echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - * Reasons for audit failure * :\\n$l_output2\"
      [ -n \"$l_output\" ] && echo -e \"- * Correctly configured * :\\n$l_output\\n\"
      exit 1
    fi").stdout do
    it { should match(/PASS/) }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.1.13_Ensure_SUID_and_SGID_files_are_reviewed' do
  title 'Ensure SUID and SGID files are reviewed'
  desc  "
    The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID or SGID program is to enable users to perform functions (such as changing their password) that require root privileges.

    Rationale: There are valid reasons for SUID and SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different checksum than what from the package. This is an indication that the binary may have been replaced.
  "
  impact 0.0
  describe 'This recommendation cannot be checked automatically' do
    skip "Run the following script to generate a list of SUID and SGID files:
      #!/usr/bin/env bash
      {
        l_output=\"\" l_output2=\"\"
        a_suid=(); a_sgid=() # initialize arrays
        while IFS= read -r l_mount_point; do
            if ! grep -Pqs '^\h*\/run\/usr\b' <<< \"$l_mount_point\" && ! grep -Pqs -- '\bnoexec\b' <<< \"$(findmnt -krn \"$l_mount_point\")\"; then
              while  IFS= read -r -d $'\0' l_file; do
                  if [ -e \"$l_file\" ]; then
                    l_mode=\"$(stat -Lc '%#a' \"$l_file\")\"
                    [ $(( $l_mode & 04000 )) -gt 0 ] && a_suid+=(\"$l_file\")
                    [ $(( $l_mode & 02000 )) -gt 0 ] && a_sgid+=(\"$l_file\")
                  fi
              done < <(find \"$l_mount_point\" -xdev -type f \( -perm -2000 -o -perm -4000 \) -print0 2>/dev/null)
            fi
        done <<< \"$(findmnt -Derno target)\"
        if ! (( ${#a_suid[@]} > 0 )); then
            l_output=\"$l_output\n - No executable SUID files exist on the system\"
        else
            l_output2=\"$l_output2\n - List of \"$(printf '%s' \"${#a_suid[@]}\")\" SUID executable files:\n$(printf '%s\n' \"${a_suid[@]}\")\n - end of list -\n\"
        fi
        if ! (( ${#a_sgid[@]} > 0 )); then
            l_output=\"$l_output\n - There are no SGID files exist on the system\"
        else
            l_output2=\"$l_output2\n - List of \"$(printf '%s' \"${#a_sgid[@]}\")\" SGID executable files:\n$(printf '%s\n' \"${a_sgid[@]}\")\n - end of list -\n\"
        fi
        [ -n \"$l_output2\" ] && l_output2=\"$l_output2\n- Review the preceding list(s) of SUID and/or SGID files to\n- ensure that no rogue programs have been introduced onto the system.\n\"
        unset a_arr; unset a_suid; unset a_sgid # Remove arrays
        # If l_output2 is empty, Nothing to report
        if [ -z \"$l_output2\" ]; then
            echo -e \"\n- Audit Result:\n$l_output\n\"
        else
            echo -e \"\n- Audit Result:\n$l_output2\n\"
            [ -n \"$l_output\" ] && echo -e \"$l_output\n\"
        fi
      }
      Note: on systems with a large number of files, this may be a long running process
      Ensure that no rogue SUID or SGID programs have been introduced into the system. Review the files returned by the action in the above script and confirm the integrity of these binaries."
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.1_Ensure_accounts_in_etcpasswd_use_shadowed_passwords' do
  title 'Ensure accounts in /etc/passwd use shadowed passwords'
  desc  "
    Local accounts can uses shadowed passwords.  With shadowed passwords, The passwords are saved in shadow password file, /etc/shadow , encrypted by a salted one-way hash. Accounts with a shadowed password have an x in the second field in /etc/passwd .

    Rationale: The /etc/passwd file also contains information like user ID's and group ID's that are used by many system programs. Therefore, the /etc/passwd file must remain world readable. In spite of encoding the password with a randomly-generated one-way hash function, an attacker could still break the system if they got access to the /etc/passwd file. This can be mitigated by using shadowed passwords, thus moving the passwords in the /etc/passwd file to /etc/shadow . The /etc/shadow file is set so only root will be able to read and write. This helps mitigate the risk of an attacker gaining access to the encoded passwords with which to perform a dictionary attack.

    **Note:**

    * All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
    *  A user account with an empty second field in /etc/passwd allows the account to be logged into by providing only the username.
  "
  impact 1.0
  describe passwd.where { password != 'x' } do
    its('entries') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.2_Ensure_etcshadow_password_fields_are_not_empty' do
  title 'Ensure /etc/shadow password fields are not empty'
  desc  "
    An account with an empty password field means that anybody may log in as that user without providing a password.

    Rationale: All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
  "
  impact 1.0
  only_if('This control require sudo permission to execute') { bash('id').stdout =~ /uid\=0\(root\)/ }
  describe shadow.where { password == '' } do
    its('entries') { should be_empty }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.3_Ensure_all_groups_in_etcpasswd_exist_in_etcgroup' do
  title 'Ensure all groups in /etc/passwd exist in /etc/group'
  desc  "
    Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not in /etc/group .

    Rationale: Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security since group permissions are not properly managed.
  "
  impact 1.0
  passwd_gids = passwd.gids.map { |gid| gid.to_i }
  etc_group_gids = etc_group.gids
  describe.one do
    describe 'All groups in /etc/passwd exist in /etc/group' do
      it { expect(passwd_gids).to be_in etc_group_gids }
    end
    describe passwd do
      its('uids') { should be_empty }
      its('gids') { should be_empty }
    end
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.4_Ensure_shadow_group_is_empty' do
  title 'Ensure shadow group is empty'
  desc  "
    The shadow group allows system programs which require access the ability to read the /etc/shadow file. No users should be assigned to the shadow group.

    Rationale: Any users assigned to the shadow group would be granted read access to the /etc/shadow file. If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed passwords to break them. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert additional user accounts.
  "
  impact 1.0
  describe file('/etc/group') do
    its('content') { should_not match(/^shadow:[^:]*:[^:]*:[^:]+$/) }
  end
  describe passwd do
    its('gids') { should_not include etc_group.where(group_name: 'shadow').gids[0].to_s }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.5_Ensure_no_duplicate_UIDs_exist' do
  title 'Ensure no duplicate UIDs exist'
  desc  "
    Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the /etc/passwd file and change the UID field.

    Rationale: Users must be assigned unique UIDs for accountability and to ensure appropriate access protections.
  "
  impact 1.0
  describe passwd do
    its('uids') { should_not contain_duplicates }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.6_Ensure_no_duplicate_GIDs_exist' do
  title 'Ensure no duplicate GIDs exist'
  desc  "
    Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the /etc/group file and change the GID field.

    Rationale: User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
  "
  impact 1.0
  describe etc_group do
    its('gids') { should_not contain_duplicates }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.7_Ensure_no_duplicate_user_names_exist' do
  title 'Ensure no duplicate user names exist'
  desc  "
    Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to manually edit the /etc/passwd file and change the user name.

    Rationale: If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in /etc/passwd . For example, if \"test4\" has a UID of 1000 and a subsequent \"test4\" entry has a UID of 2000, logging in as \"test4\" will use UID 1000. Effectively, the UID is shared, which is a security problem.
  "
  impact 1.0
  describe passwd do
    its('users') { should_not contain_duplicates }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.8_Ensure_no_duplicate_group_names_exist' do
  title 'Ensure no duplicate group names exist'
  desc  "
    Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator to manually edit the /etc/group file and change the group name.

    Rationale: If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in /etc/group . Effectively, the GID is shared, which is a security problem.
  "
  impact 1.0
  describe etc_group do
    its('groups') { should_not contain_duplicates }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.9_Ensure_local_interactive_user_home_directories_are_configured' do
  title 'Ensure local interactive user home directories are configured'
  desc  "
    The user home directory is space defined for the particular user to set local environment variables and to store personal files.  While the system administrator can establish secure permissions for users' home directories, the users can easily override these. Users can be defined in /etc/passwd without a home directory or with a home directory that does not actually exist.

    Rationale: Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory. Group or world-writable user home directories may enable malicious users to steal or modify other users' data or to gain another user's system privileges. If the user's home directory does not exist or is unassigned, the user will be placed in \"/\" and will not be able to write any files or have local environment variables set.
  "
  impact 1.0
  local_interactive_user_home_directories = bash("#!/usr/bin/env bash
    {
      l_output=\"\" l_output2=\"\" l_heout2=\"\" l_hoout2=\"\" l_haout2=\"\"
      l_valid_shells=\"^($( awk -F\\/ '$NF != \"nologin\" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' | paste -s -d '|' - ))$\"
      unset a_uarr && a_uarr=()
      while read -r l_epu l_eph; do
        a_uarr+=(\"$l_epu $l_eph\")
      done <<< \"$(awk -v pat=\"$l_valid_shells\" -F: '$(NF) ~ pat { print $1 \" \" $(NF-1) }' /etc/passwd)\"
      l_asize=\"${#a_uarr[@]}\"
      [ \"$l_asize \" -gt \"10000\" ] && echo -e \"\\n  ** INFO **\\n  - \\\"$l_asize\\\" Local interactive users found on the system\\n  - This may be a long running check\\n\"
      while read -r l_user l_home; do
        if [ -d \"$l_home\" ]; then
            l_mask='0027'
            l_max=\"$( printf '%o' $(( 0777 & ~$l_mask)) )\"
            while read -r l_own l_mode; do
              [ \"$l_user\" != \"$l_own\" ] && l_hoout2=\"$l_hoout2\\n  - User: \\\"$l_user\\\" Home \\\"$l_home\\\" is owned by: \\\"$l_own\\\"\"
              if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
                  l_haout2=\"$l_haout2\\n  - User: \\\"$l_user\\\" Home \\\"$l_home\\\" is mode: \\\"$l_mode\\\" should be mode: \\\"$l_max\\\" or more restrictive\"
              fi
            done <<< \"$(stat -Lc '%U %#a' \"$l_home\")\"
        else
            l_heout2=\"$l_heout2\\n  - User: \\\"$l_user\\\" Home \\\"$l_home\\\" Doesn't exist\"
        fi
      done <<< \"$(printf '%s\\n' \"${a_uarr[@]}\")\"
      [ -z \"$l_heout2\" ] && l_output=\"$l_output\\n   - home directories exist\" || l_output2=\"$l_output2$l_heout2\"
      [ -z \"$l_hoout2\" ] && l_output=\"$l_output\\n   - own their home directory\" || l_output2=\"$l_output2$l_hoout2\"
      [ -z \"$l_haout2\" ] && l_output=\"$l_output\\n   - home directories are mode: \\\"$l_max\\\" or more restrictive\" || l_output2=\"$l_output2$l_haout2\"
      [ -n \"$l_output\" ] && l_output=\"  - All local interactive users:$l_output\"
      if [ -z \"$l_output2\" ]; then # If l_output2 is empty, we pass
        echo -e \"\\n- Audit Result:\\n  ** PASS **\\n - * Correctly configured * :\\n$l_output\"
        exit 0
      else
        echo -e \"\\n- Audit Result:\\n  ** FAIL **\\n - * Reasons for audit failure * :\\n$l_output2\"
        [ -n \"$l_output\" ] && echo -e \"\\n- * Correctly configured * :\\n$l_output\"
        exit 1
      fi
    }").stdout
  describe local_interactive_user_home_directories do
    it { should match /PASS/ }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_7.2.10_Ensure_local_interactive_user_dot_files_access_is_configured' do
  title 'Ensure local interactive user dot files access is configured'
  desc  "
    While the system administrator can establish secure permissions for users' \"dot\" files, the users can easily override these.

    * .forward file specifies an email address to forward the user's mail to.
    * .rhost file provides the \"remote authentication\" database for the rcp, rlogin, and rsh commands and the rcmd() function. These files bypass the standard password-based user authentication mechanism. They specify remote hosts and users that are considered trusted (i.e. are allowed to access the local system without supplying a password)
    * .netrc file contains data for logging into a remote host or passing authentication to an API.
    * .bash_history file keeps track of the user&#x2019;s commands.

    Rationale: User configuration files with excessive or incorrect access may enable malicious users to steal or modify other users' data or to gain another user's system privileges.
  "
  impact 1.0
  local_interactive_user_dot_files_access = bash("#!/usr/bin/env bash\n\n
  {
  a_output2=(); a_output3=()
  l_maxsize=\"1000\"
  l_valid_shells=\"^($( awk -F\\/ '$NF != \"nologin\" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' | paste -s -d '|' - ))$\"
  a_user_and_home=()
  while read -r l_local_user l_local_user_home; do
      [[ -n \"$l_local_user\" && -n \"$l_local_user_home\" ]] && a_user_and_home+=(\"$l_local_user:$l_local_user_home\")
  done <<< \"$(awk -v pat=\"$l_valid_shells\" -F: '$(NF) ~ pat { print $1 \" \" $(NF-1) }' /etc/passwd)\"
  l_asize=\"${#a_user_and_home[@]}\"
  [ \"${#a_user_and_home[@]}\" -gt \"$l_maxsize\" ] && printf '%s\\n' \"\" \"  ** INFO **\"
  \"  - \\\"$l_asize\\\" Local interactive users found on the system\"
  \"  - This may be a long running check\" \"\"
  file_access_chk()
  {
      a_access_out=()
      l_max=\"$( printf '%o' $(( 0777 & ~$l_mask)) )\"
      if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
        a_access_out+=(\"  - File: \\\"$l_hdfile\\\" is mode: \\\"$l_mode\\\" and should be mode: \\\"$l_max\\\" or more restrictive\")
      fi
      if [[ ! \"$l_owner\" =~ ($l_user) ]]; then
        a_access_out+=(\"  - File: \\\"$l_hdfile\\\" owned by: \\\"$l_owner\\\" and should be owned by \\\"${l_user//|/ or }\\\"\")
      fi
      if [[ ! \\\"$l_gowner\\\" =~ ($l_group) ]]; then
        a_access_out+=(\"  - File: \\\"$l_hdfile\\\" group owned by: \\\"$l_gowner\\\" and should be group owned by \\\"${l_group//|/ or }\\\"\")
      fi
  }
  while IFS=: read -r l_user l_home; do
      a_dot_file=(); a_netrc=(); a_netrc_warn=(); a_bhout=(); a_hdirout=()
      if [ -d \"$l_home\" ]; then
        l_group=\"$(id -gn \"$l_user\" | xargs)\";l_group=\"${l_group// /|}\"
        while IFS= read -r -d $'\\0' l_hdfile; do
            while read -r l_mode l_owner l_gowner; do
              case \"$(basename \"$l_hdfile\")\" in
                  .forward | .rhost )
                    a_dot_file+=(\"  - File: \\\"$l_hdfile\\\" exists\") ;;
                  .netrc )
                    l_mask='0177'; file_access_chk
                    if [ \"${#a_access_out[@]}\" -gt 0 ]; then
                        a_netrc+=(\"${a_access_out[@]}\")
                    else
                        a_netrc_warn+=(\"   - File: \\\"$l_hdfile\\\" exists\")
                    fi ;;
                  .bash_history )
                    l_mask='0177'; file_access_chk
                    [ \"${#a_access_out[@]}\" -gt 0 ] && a_bhout+=(\"${a_access_out[@]}\") ;;
                  * )
                    l_mask='0133'; file_access_chk
                    [ \"${#a_access_out[@]}\" -gt 0 ] && a_hdirout+=(\"${a_access_out[@]}\") ;;
              esac
            done < <(stat -Lc '%#a %U %G' \"$l_hdfile\")
        done < <(find \"$l_home\" -xdev -type f -name '.*' -print0)
      fi
      if [[ \"${#a_dot_file[@]}\" -gt 0 || \"${#a_netrc[@]}\" -gt 0 || \"${#a_bhout[@]}\" -gt 0 || \"${#a_hdirout[@]}\" -gt 0 ]]; then
        a_output2+=(\" - User: \\\"$l_user\\\" Home Directory: \\\"$l_home\\\"\" \"${a_dot_file[@]}\" \"${a_netrc[@]}\" \"${a_bhout[@]}\" \"${a_hdirout[@]}\")
      fi
      [ \"${#a_netrc_warn[@]}\" -gt 0 ] && a_output3+=(\" - User: \\\"$l_user\\\" Home Directory: \\\"$l_home\\\"\" \"${a_netrc_warn[@]}\")
  done <<< \"$(printf '%s\\n' \"${a_user_and_home[@]}\")\"
  if [ \"${#a_output2[@]}\" -le 0 ]; then # If l_output2 is empty, we pass
      [ \"${#a_output3[@]}\" -gt 0 ] && printf '%s\\n' \"  ** WARNING **\" \"${a_output3[@]}\"
      printf '%s\\n' \"- Audit Result:\" \"  ** PASS **\"
  else
      printf '%s\\n' \"- Audit Result:\" \"  ** FAIL **\" \" - * Reasons for audit failure * :\" \"${a_output2[@]}\" \"\"
      [ \"${#a_output3[@]}\" -gt 0 ] && printf '%s\\n' \"  ** WARNING **\" \"${a_output3[@]}\"
  fi
  }").stdout
  describe local_interactive_user_dot_files_access do
    it { should match /PASS/ }
  end
end
