# Using DQS with SpamAssassin

This repository contains the configuration files and a plugin written for SpamAssassin, (https://spamassassin.apache.org/) for use with Spamhaus Technology Data Query Service (DQS) product.

***

### Table of contents
- [What is DQS](#what-is-dqs)?
- [What zones are available with DQS](#what-zones-are-available-with-dqs)?
- [What are the advantages of DQS](#what-are-the-advantages-of-dqs)?
- [How does DQS Perform](#how-does-dqs-perform)?
	- [HBL performance boost](#hbl-performance-boost)
- [What is the licensing for DQS](#what-is-the-licensing-for-dqs)?
- [What is the difference between paid-for and free DQS](#what-is-the-difference-between-paid-for-and-free-dqs)?
- [How do I register a DQS key](#how-do-i-register-a-dqs-key)?
- [Prerequisites](#prerequisites)
- [Conventions](#conventions)
- Installation instructions
	- [Install from Github](#install-from-github)
	- [Install from FreeBSD ports](#install-from-freebsd-ports)
	- [Install the plugin in a MDaemon server](#install-the-plugin-in-a-mdaemon-server)
- [Testing your setup](#testing-your-setup)
- [Plugin internals](#plugin-internals)
- [Final recommendations](#final-recommendations)
- [Support and feedback](#support-and-feedback)
- [Acnowledgements](#acnowledgements)

***

#### What is DQS?

Data Query Service (DQS) is a set of DNSBLs, updated in real-time, operated by Spamhaus Technology ([https://www.spamhaustech.com](https://www.spamhaustech.com))

***

#### What zones are available with DQS?

All zones, their definitions, and all possible return codes are documented [here](https://docs.spamhaustech.com/10-data-type-documentation/datasets/030-datasets.html)

***

#### What are the advantages of DQS?

With DQS, Spamhaus provides real time updates instead of the one-minute-delayed updates that are used by the public mirrors and the RSYNC feed.
Sixty seconds doesn't seem like much, but when dealing with hailstormers they are *crucial*: the increase in catch rate between the public mirrors and DQS is mostly due to the real time updates.

Along with the above advantage, free DQS users will also get two new zones to query, Zero Reputation Domains (ZRD) and AuthBL. Paid-for DQS users will also get access to the Hash BlockList (HBL).

ZRD automatically adds newly-registered as well as previously-dormant domains to a block list for 24 hours. It also gives return codes that indicate the age of the domain (in hours) since first detection.

AuthBL is primarily designed for use by anyone operating a submission SMTP server. It is a list of IPs that are known to host bots that use stolen credentials to spam. If one of your customers gets their credentials stolen, AuthBL greatly mitigates the ability of botnets to abuse the account, and keeps your MTAs safe from collateral damage.

HBL is a zone dedicated to deal with sextortions/scam cryptowallets, dropbox emails and malicious files.

***

#### How does DQS perform?

You can [see it yourself](https://www.virusbulletin.com/testing/results/latest/vbspam-email-security). We are independently tested by Virus Bulletin, a company that tests both DQS and public mirror performances. The difference between them is that DQS catches up to 42% more spam than our public mirrors.
NOTE: Results on VBSpam are achieved by using *only* the DQS dataset, meaning that if you just add an antivirus to your email filtering setup you can potentially reach the same performance as other commercial antispam products.

#### HBL performance boost

While we know that every scenario is different, our in the field observations made using the Virus Bulletin spam feed shows that including HBL in your antispam setup could roughly boost spam detection from 0,3% up to slightly more than 1%

***

#### What is the licensing for DQS?

The usage terms are [the same](https://www.spamhaus.org/organization/dnsblusage/) as the terms for our public mirrors, meaning that if you already use our public mirrors you are entitled to a free DQS key.

***

#### What is the difference between paid-for and free DQS?

With free DQS you have access to ZRD and AuthBL, and you must abide by the [free usage policy limits](https://www.spamhaus.org/organization/dnsblusage/) 

With a paid subscription there is no query limit, and access to HBL (the new zone that deals with cryptovalues, emails and malware) is included. 

All the technical information about HBL is available [here](https://docs.spamhaustech.com/10-data-type-documentation/datasets/030-datasets.html#hbl)

If you have a free DQS subscription and would like to trial HBL, please send an email to [sales@spamteq.com](mailto:sales@spamteq.com) including your customer ID, and you will be contacted by one of our representative to activate a 30 day trial.

***

#### How do I register a DQS key?

Just go [here](https://www.spamhaustech.com/dqs/) and complete the registration procedure. After you register an account, go to [this](https://portal.spamhaustech.com/manuals/dqs/) page and you'll find the DQS key under section "1.0 Datafeed Query Service".

***

#### Prerequisites

You need a DQS key along with an existing SpamAssassin 3.4.1+ installation on your system. These instructions do not cover the initial SpamAssassin installation. To correctly install SpamAssassin, please refer to instructions applicable to your SpamAssassin distribution.

***

#### Conventions

We are going to use some abbreviations and placeholders:

 * SA: SpamAssassin
 * SH: Spamhaus
 * *configuration directory*: whenever you find these italic words, we are referring to SA's configuration directory. Depending on your distribution it may be `/etc/spamassassin` or `/etc/mail/spamassassin` or something else.
 * Whenever you see the box below, it means that you need to enter the command on your shell:
```
	$ command
```
 * Whenever you see the box below, it means that you need to enter the command on a shell with *root privileges*:
```
	# command
```

## Installation instructions

#### Install from Github

Start by downloading the latest package:

```
	$ git clone https://github.com/spamhaus/spamassassin-dqs
	Cloning into 'spamassassin-dqs'...
	remote: Enumerating objects: 11, done.
	remote: Counting objects: 100% (11/11), done.
	remote: Compressing objects: 100% (9/9), done.
	remote: Total 11 (delta 0), reused 11 (delta 0), pack-reused 0
	Unpacking objects: 100% (11/11), done.
```

A subdirectory called `spamassassin-dqs` will be created. Within it you will find the following files:

- `README.md`. This is just a pointer to this document.
- `Changelog.md`. The changes log file
- `hbltest.sh`. A script that helps you know if your DQS key is HBL enabled
- `sh.pre`. This file is the loader for the plugin
- `SH.pm`. This is a dedicated SA plugin written by SH that overcomes some of SA's limitations
- `sh.cf`. This file contains lookup redefinitions and will need to be edited (see below)
- `sh_scores.cf`. In this file we override some of SA's default rule scoring
- `sh_hbl.cf`. Definitions for HBL lookups
- `sh_hbl_scores.cf`. Definitions for HBL lookups scores
- `LICENSE`. The Apache software license
- `NOTICE`. A file containing copyright notices

Next, configure your DQS key. Assuming your key is `aip7yig6sahg6ehsohn5shco3z`, execute the following commands:

```
	$ cd spamassassin-dqs
	$ sed -i -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' sh.cf
	$ sed -i -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' sh_hbl.cf
```

If you are using FreeBSD, the commands change slightly:

```
	$ cd spamassassin-dqs
	$ sed -i "" -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' sh.cf
	$ sed -i "" -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' sh_hbl.cf
```

There will be no output, but the key will be inserted into `sh.cf` and `sh_hbl.cf` in all the needed places.

Edit `sh.pre` with your editor of choice, and look at the first line:

```
	loadplugin       Mail::SpamAssassin::Plugin::SH <config_directory>/SH.pm
```

You will need to replace `<config_directory>` with your actual *configuration directory*. So, for example, if your *configuration directory* is `/etc/mail/spamassassin`, the line will become:

```
	loadplugin       Mail::SpamAssassin::Plugin::SH /etc/mail/spamassassin/SH.pm
```

We provide a simple script to help you verify whether your DQS key is HBL enabled or not. Use this script to understand what files to copy in your SpamAssassin config directory. You only need to run the script and input your DQS key.

Assuming the example key ```aip7yig6sahg6ehsohn5shco3z``` *is* DQS enabled, run the script and the output will confirm whether your key is HBL enabled:

```
	$ sh hbltest.sh
	Please input your DQS key: aip7yig6sahg6ehsohn5shco3z
	Looking up test record for HBL... done
	Your DQS key aip7yig6sahg6ehsohn5shco3z is enabled for HBL
	You can copy sh_hbl.cf and sh_hbl_scores.cf if you want HBL enabled
```

If your key is not HBL enabled (meaning that you registered a FREE DQS key and did not use a paid subscription) the output will be the following:

```
	$ sh hbltest.sh 
	Please input your DQS key: aip7yig6sahg6ehsohn5shco3z
	Looking up test record for HBL... done
	Your DQS key aip7yig6sahg6ehsohn5shco3z is -=NOT=- enabled for HBL
	Please *do not* copy sh_hbl.cf and sh_hbl_scores.cf
```

Based on the output of the above script, copy the relevant .cf files in SA *configuration directory*.

If you have an HBL enabled key, and assuming the *configuration directory* is `/etc/mail/spamassassin` do the following:

```
	# cp SH.pm /etc/mail/spamassassin
	# cp sh.cf /etc/mail/spamassassin
	# cp sh_scores.cf /etc/mail/spamassassin
	# cp sh_hbl.cf /etc/mail/spamassassin
	# cp sh_hbl_scores.cf /etc/mail/spamassassin
	# cp sh.pre /etc/mail/spamassassin
```

If your key is *not* HBL enabled, this is what needs to be done:

```
	# cp SH.pm /etc/mail/spamassassin
	# cp sh.cf /etc/mail/spamassassin
	# cp sh_scores.cf /etc/mail/spamassassin
	# cp sh.pre /etc/mail/spamassassin
```

We strongly suggest to not copy the HBL files if your key is not HBL enabled, as the lookups timout will very likely slow SA email processing.

Next, test the setup by running:

```
	# spamassassin --lint
```
	
This command checks the whole SA installation; if you don't see any output then congratulations! You successfully installed SH's SA setup. You only need to restart SpamAssassin to have the plugin loaded.

In case you tried installing the plugin with a wrong SpamAssassin version (< 3.4.1) you will receive a warning similar to the following :

```
	# spamassassin --lint

	SHPlugin: ************************** WARNING *************************
	SHPlugin: This plugin will work only with SpamAssassin 3.4.1 and above
	SHPlugin: Your currently installed version is 3.4.0
	SHPlugin: ******************** THIS WILL NOT WORK ********************
	SHPlugin: Remove sh.pre file or update SpamAssassin
```

Be sure to follow the instructions and remove all the previously copied files. As stated above, the plugin will work only on SpamAssassin 3.4.1 and above. 

***

#### Install from FreeBSD ports

[lrosenman](https://github.com/lrosenman) maintains a FreeBSD port of our plugin. We don't give support for this port, but if you want to use it, the instructions are as follows:

```
	# pkg install spamassassin-dqs
```
and then follow the instructions.

Or, if using ports:

```
	$ cd /usr/ports/mail/spamassassin-dqs
	$ sudo make install
```

#### Install the plugin in a MDaemon server

Please see the file [MDaemon.md](MDaemon.md) for instructions

## Testing your setup

Once you succesfully installed the plugin, you could head to [http://blt.spamhaus.com](http://blt.spamhaus.com) and test if you have correctly installed everything. 

**Please read the docs carefully**, as a "delivered" response with a red flag **doesn't always mean you missed something**; it depends on your setup. You should always check all the headers of any email that the BLT sends and look for spam headers, usually, but not always: "X-Spam-Flag: Yes" or "X-Spam: Yes".

***

## Plugin internals

While we acknowledge SpamAssassin's abilities at stopping spam with only minor tweaking of the default config, there are some key uses of our datasets that can only be fully taken advantage of by writing some special SA functions. That is why we decided to develop this special plugin that includes these functions:

 * `check_sh_helo`.
This function checks the domain used in the HELO/EHLO string against DBL and ZRD.

 * `check_sh_headers`. 
This function takes the domain out of the *From* , *Reply-to* , *Envelope From*, *Return-Path* header lines and then checks the domain against DBL and ZRD.

 * `check_sh_bodyemail`.
This function scans the email body looking for email addresses. For all email addresses found, it extracts the domain and check it against DBL and ZRD. This approach has been proven useful, for example, in some dating-scam campaigns.

 * `check_sh_bodyemail_ns`.
This function scans the email body looking for email addresses. For all email addresses found, it extracts the domain and then checks its authoritative nameservers IPs in SBL (beta, not used, but you are encouraged to try it).

 * `check_sh_reverse`
This function checks the reverse DNS (rDNS) of the last untrusted relay in both DBL and ZRD

 * `check_sh_bodyuri_a`
 This function scans the email body and looks for URLs; when one is found the hostname is then resolved, and the resulting IP address is checked in SBL and CSS.

 * `check_sh_bodyuri_ns`
 This function scans the email body and looks for URLs; when one is found it takes the domain's authoritative nameservers IPs and checks them in SBL (beta, not used, but you are encouraged to try it).
 
 * `check_sh_hostname`
 This function extracts whole hostnames starting from URLs in the email body and is used to check them in the abused-legit component of DBL
 
 * `check_sh_crypto`
 This functions looks for cryptowallets in the email body and checks them in HBL. As of today, we support the following cryptos:
 	 - BTC
	 - BCH
	 - XMR
	 - LTC
	 - XRP
	 - ETH
	 
* `check_sh_attachment`
This functions computes the hash of all the attachments and checks them in HBL, looking for confirmed or suspect malware.

* `check_sh_emails`
This functions collects all email addresses from headers and body and checks their hashes in HBL.
 
 
 ***
 
## Final recommendations
 
The configuration in the VBSpam survey makes exclusive use of our data, since our goal was to certify their quality, and to keep an eye on how we perform in the field.

While the results are reasonably good, the malware/phishing scoring can certainly be improved by employing some additional actions that we recommend.

- Install an antivirus software on your mailserver;
- The modern rule of thumb for receiving email should be to "stay defensive", which is why we recommend doing basic attachment filtering by dropping all emails that contains potentially hazardous attachments, at *minimum* all file extensions that match this regex:

```
(exe|vbs|pif|scr|bat|cmd|com|cpl|dll|cpgz|chm|js|jar|wsf)
```

- You should also drop, by default, all Office documents with macros.

## Support and feedback

We would be happy to receive your feedback! If you notice any problems with this installation, please open a Github issue and we'll do our best to help you.

Remember that we are only going to support the latest version, so before opening an issue, please be sure to be running the up-to-date code from this Github repository.

## Acknowledgements

We'd like to thank everyone for their suggestions and contributions!
