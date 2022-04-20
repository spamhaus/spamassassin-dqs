Changelog for SpamAssassin DQS Plugin 

- 200422
	- Removed useless syslog functions and made the plugin compatible with MDaemon
	- Minor fixes
	- Tagged version 1.2.2

- 310122
	- Added functions to check whole hostnames in DBL
	- Minor fixes
	- Tagged version 1.2.0
	
- 140721
	- Fixed scores on the abused section
	- Tagged version 1.1.3

- 091220
	- Fixed issues thanks to robertmathews
	- Fixes edge case spotted in check_sh_email
	- Tagged version 1.1.2

- 250820
	- Fixed issue with wrong usage of check_rbl_sub()
	- Scores adjusted to work with the default SpamAssassin required_score of 5
	  This is a work in progress, scores may change again in future based on feedback

- 270520
	- Added SA version checking at lint time

- 190520 (v.1.1.0)
	- Tagged version 1.1.0 (no code changes)
	- Same tag as Rspamd plugin with HBL

- 300420
	- Added a Changelog file :)
	- Made the plugin compatible with SpamAssassin 3.4.1
	- Added support for the HBL zone
	- Various fixes
