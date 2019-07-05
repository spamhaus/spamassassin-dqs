# Use DQS with Spamassassin

This repository contains configuration files and a plugin written for Spamassassin (https://spamassassin.apache.org/) that enables you to use Spamhaus Technology Data Query Service (DQS) product

### Table of contents
- [What is DQS](#what-is-dqs)?
- [How does DQS Performs](#how-does-dqs-performs)?
- [What is the licensing for DQS](#what-is-the-licensing-for-dqs)?
- [How do I register a DQS key](#how-do-i-register-a-dqs-key)?
- [Prerequisites](#prerequisites)
- [Conventions](#conventions)
- Installation instructions
	- [Install from Github](#install-from-github)
	- [Install from FreeBSD ports](#install-from-freebsd-ports)
- [Plugin internals](#plugin-internals)
- [Final recommendations](#final-recommendations)
- [Support and feedback](#support-and-feedback)
- [Acnowledgements](#acnowledgements)
#### What is DQS

DQS is a set of DNSBLs with real time updates.

#### How does DQS performs

You can [see it by yourself](https://www.virusbulletin.com/testing/results/latest/vbspam-email-security). We are independently tested by Virus Bulletin, that tests both DQS and public mirror performances. The difference is that DQS catches up to 42% more spam than our public mirrors.
And please be aware that that results on VBSpam are achieved by using *only* the DQS dataset, meaning that if you just add an antivirus to your email filtering setup you can possibly reach the same performance as other commercial antispam products.

#### What is the licensing for DQS?

The usage terms are [the same](https://www.spamhaus.org/organization/dnsblusage/) as the ones for our public mirrors, meaning that if you already use our public mirrors you are entitled for a free DQS key.

#### How do I register a DQS key?

It's very easy, just go [here](https://www.spamhaustech.com/dqs/) and complete the registration procedure. After you register an account, go to [this](https://portal.spamhaustech.com/src/manual/dqs/) page and note the DQS key.

#### Prerequisites

You naturally need a DQS key along with Spamassassin 3.4.1+ already installed on your system. These instructions do not cover the initial Spamassassin installation. 
To correctly install Spamassassin please refer to instructions applicable to your distribution.

The scores in this configuration files are weighted for a `required_score` of 4 instead of the default 6. If you use a different `required_score` adjust the values accordingly.

#### Conventions

We are going to use some abbreviations and placeholders:

 * SA: SpamAssassin
 * SH: Spamhaus
 * *configuration directory*: whenever you'll find these italic words, we will refer to SA's configuration directory. Depending on your distribution it may be `/etc/spamassassin` or `/etc/mail/spamassassin` or other
 * whenever you find the box below, it means that you need to enter the command on your shell:
```
	$ command
```
 * whenever you find the box below, it means that you need to enter the command on a shell with root privileges:
```
	# command
```

## Installation instructions

####Install from Github

Start with downloading the latest package:

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
- `SH.pm`. This is a dedicated SA plugin written by SH that overcomes some of SA's limitations
- `sh.cf`. This file contains lookup redefinitions and will need to be edited (see below)
- `sh_scores.cf`. In this file we override some of SA's default rule scoring
- `LICENSE`. The Apache software license
- `NOTICE`. A file containing copyright notices

Now it's time to configure your DQS key. Assuming your key is `aip7yig6sahg6ehsohn5shco3z`, execute the following command:

```
	$ cd spamassassin-dqs
	$ sed -i -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' sh.cf
```

If you are on FreeBSD then the command slightly changes:

```
	$ cd spamassassin-dqs
	$ sed -i "" -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' sh.cf
```

There will be no output, but your key will be placed inside `sh.cf` in all the needed places.

Edit `sh.cf` with your editor of choice, and take a look at the first line:

```
	loadplugin       Mail::SpamAssassin::Plugin::SH <config_directory\>/SH.pm
```

You will need to replace `<config_directory\>` with your actual *configuration directory*. So, for example, if your *configuration directory* is `/etc/mail/spamassassin`, the line will become:

```
	loadplugin       Mail::SpamAssassin::Plugin::SH /etc/mail/spamassassin/SH.pm
```

Finally, copy the files in Spamassassin's *configuration directory*. Assuming it is `/etc/mail/spamassassin`, you'll need to issue these commands:

```
	# cp SH.pm /etc/mail/spamassassin
	# cp sh.cf /etc/mail/spamassassin
	# cp sh_scores.cf /etc/mail/spamassassin
```

Now test the setup by running:

```
	# spamassassin --lint
```
	
This command checks the whole SA installation; if you don't see any output then congratulations! You successfully installed SH's SA setup. You only need to restart Spamassassin to have the plugin loaded.

#### Install from FreeBSD ports

[lrosenman](https://github.com/lrosenman) is mantaining a FreeBSD port of our plugin. We don't give support for this port, but if you want to use it the instructions are as follows:

```
	# pkg install spamassassin-dqs
```
and then follow the  instructions.

Or, if using ports:

```
	$ cd /usr/ports/mail/spamassassin-dqs
	$ sudo make install
```

## Plugin internals

While we undoubtedly recognize Spamassassin's abilities at stopping spam with only minor tweakings to the default config, there are some key uses of our datasets that can be fully taken advantage of only by writing some special SA functions. This is why we decided to develop this special plugin that includes these functions:

 * `check_sh_helo`.
This function checks the domain used in the HELO/EHLO string against DBL and ZRD.

 * `check_sh_headers`. 
This function takes the domain out of the *From* , *Reply-to* , *Envelope From*, *Return-Path* header lines and then checks the domain against DBL and ZRD.

 * `check_sh_bodyemail`.
This function scans the email body looking for email addresses. For all email addresses found, it extracts the domain and check it against DBL and ZRD. This approach has been proven useful, for example, in some dating scams campaign.

 * `check_sh_bodyemail_ns`.
This function scans the email body looking for email addresses. For all email addresses found, it extracts the domain and then cheks it's authoritative nameservers IPs in SBL (beta, not used but you are encouraged to try it)

 * `check_sh_reverse`
This function checks the reverse DNS (rDNS) of the last untrusted relay in both DBL and ZRD

 * `check_sh_bodyuri_a`
 This function scans the email body and looks for URLs; when one is found the hostname is then resolved and the resulting IP address is checked in SBL and CSS

 * `check_sh_bodyuri_ns`
 This function scans the email body and looks for URLs; when one is found it takes the domain's authoritative nameservers IPs and checks them in SBL (beta, not used but you are encouraged to try it)
 
## Final recommendations
 
We already said that the configuration in the VBSpam survey make use exclusively of our data, as our goal was certifying their quality and keep an eye on how we perform in the field.

While the results are reasonably good, the malware/phishing scoring can certainly be improved through some additional actions that we recommend.

- Install an antivirus software on your mailserver
- Nowadays the rule of thumb for receiving email should be to stay defensive, that is why we recommend to do basic attachment filtering by dropping all emails that contains potentially hazardous attachments, like *at least* all file extensions that match this regex:

```
(exe|vbs|pif|scr|bat|cmd|com|cpl|dll|cpgz|chm|js|jar|wsf)
```

- You should also drop, by default, all Office documents with macros.

## Support and feedback

We would be happy to receive some feedback from you. If you notice any problem with this installation, please drop us a note at datafeed-support@spamteq.com and we'll try to do our best to help you.

Remember that we are going to support only the latest version, so please before opening a support request be sure to be running the up to date code from this github repository.

## Acnowledgements

We'd like to thank everyone for their suggestions. This plugin has been written by using other more well-written plugins as examples, especially [HashBL](https://github.com/smfreegard/HashBL/) from where we borrowed a lot of code. 