# uob_rhel9_hardening_cis_v2_0_0 

## Maintainers

This resource is maintained by the Nagarjuna Tulabandula 

## SCOPE

RHEL9 Hardening cookbook following v2.0.0 of cis hardening standard

## Syntax

## Syntax
| use case | command | example | description
| ------ | ------ | ------ | ------ |
|Remediate RHEL9 CIS compliance failures for all controls in cookbook |chef-client -o uob_rhel9_hardening_cis_v2_0_0| chef-client -o uob_rhel9_hardening_cis_v2_0_0| will run full remediation for all lv1 controls, l2 controls based on serverlevel databag |
|Remediate RHEL9 CIS compliance failures for specific control(s) in cookbook|chef-client -o uob_rhel9_hardening_cis_v2_0_0::{control id} | chef-client -o uob_rhel9_hardening_cis_v2_0_0::1.1.1.1| will only run the specific control, still subject to deviations in place |
|Rollback all changes of remediated RHEL9 CIS compliance failures based on last execution (runid)|chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback| chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback| rolls back every control within the latest runid |
|Rollback all changes (or selected (controls control id)) of remediated RHEL9 CIS compliance failures based on specific execution time (runid) |chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback -j {path_to_json_file} | chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback -j variables.json| rollback specific runid/control_id/both |


## logs and backup
**default location for logs and backup files are specified in cookbook attributes**
**Transaction Log**
```sh
/syslv/cis/cis_compliance_changelog

This file contains all changes made by this cookbook. The information stored here will be used for rolling back changes made. This will be rotated at the beginning of each cookbook/recipe execution, if the original file exceeds 10MB. 
Naming convention of rotated file is:
cis_complioance_changelog-20250320-17:47:53.053790117
```

| column | description 
| ------ | ------ | 
|Timestamp|Time when the hardening was run| 
| run ID | generated at start of cookbook run, used in references for rollbacks | 
|Path_or_command|depending on the resourced used, ether path of file that was worked on or command that was run| 
|text|misc text description for what was done| 
|resource used|chef resouce used to handle the hardening,referenced for rollbacks| 
|old value|depending on the resourced used, either previous values of file or commands that can used to reverse this hardening| 
|new value |depending on the resourced used, either the new values of file or commands that can used for this hardening| 
|control id| control id of the hardening based on v2.0 of cis stardards| 


sample log - each column delimited by ##
```sh
 Timestamp ##  run ID ## Path_or_command ## text ## resource used ## old value ## new value ## control id
20250320-14:15:07.684409364 ## 2025032064184 ## /etc/passwd ## update file ## file_perm ## 0777,root,root ## 0644,root,root ## 6.1.3
20250320-14:15:07.684409364 ## 2025032064184 ## /etc/crontab ## update file ## directory ## 0774,root,root ## 0700,root,root ## 5.1.2
20250320-17:45:59.493130774 ## 2025032055320 ## /etc/passwd ## update file ## file_perm ## 0777,root,root ## 0644,root,root ## 6.1.3
20250320-14:15:07.684409364 ## 2025102105321 ## /etc/crontab ## update file ## directory ## 0776,root,root ## 0700,root,root ## 5.1.2
20250321-15:58:47.545266537 ## 2025032171560 ## remove g+w permission from /home/venwri/.bash_history ## executed command ## execute ## chmod g+w /home/venwri/.bash_history ## chmod g-w /home/venwri/.bash_history ## 6.2.12
20250321-15:58:47.545266537 ## 2025032171560 ## remove o+w permission from /home/venwri/.bash_history ## executed command ## execute ## chmod o+w /home/venwri/.bash_history ## chmod o-w /home/venwri/.bash_history ## 6.2.12
```


**Backup files**
```sh
default location
/syslv/cis/backup_files/

sample file saved as filename-{timestamp}
/syslv/cis/backup_files/passwd-20250320-17:47:53.053790117
```


## Hardening Usage
**harden all controls**

 command : chef-client -o uob_rhel9_hardening_cis_v2_0_0

run default.rb which will remediate RHEL9 CIS compliance failures for all controls

**harden specific controls**

 command : chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback -j path/to/sample/json

sample json content
```sh
{
    "wrapper_recipe_list": [
			"6.1.3", 
			"5.1.2"
			]
}
```


## rollback Usage
**rollback specific controls**

 command : chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback -j path/to/sample/json

Rollback will be applied to changes for control ID based on latest runid  

sample json content
```sh
{
   "control_id": [
	"6.1.3",
	"6.1.4",
	"control id 3"
	]
}
```
**rollback all changes made by specific runid**

 command : chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback -j path/to/sample/json

sample json content
```sh
{
    "runid": "2025032073043"
}
```


**rollback changes made by specific runid and specific control_id**

 command : chef-client -o uob_rhel9_hardening_cis_v2_0_0::rollback -j path/to/sample/json

sample json content
```sh
 {
	"control_id": [
		"6.1.3",
		"5.1.2"
	],
	"runid": "2025032755321"
}
```

