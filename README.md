# Use DQS with Spamassassin

This repository contains configuration files and a plugin written for Spamassassin (https://spamassassin.apache.org/) that enables you to use Spamhaus Technology Data Query Service (DQS) product

- What is DQS?

DQS is a set of DNSBLs with real time updates.

- How does DQS performs?

You can [see it by yourself](https://www.virusbulletin.com/testing/results/latest/vbspam-email-security). We are independently tested by Virus Bulletin, that tests both DQS and public mirror performances. The difference is that DQS catches up to 42% more spam than our public mirrors.
And please be aware that that results on VBSpam are achieved by using *only* the DQS dataset, meaning that if you just add an antivirus to your email filtering setup you can possibly reach the same performance as other commercial antispam products.

- What is the licensing for DQS?

The usage terms are [the same](https://www.spamhaus.org/organization/dnsblusage/) as the ones for our public mirrors, meaning that if you already use our public mirrors you are entitled for a free DQS key.

- How do I register a DQS key?

It's very easy, just go [here](https://www.spamhaustech.com/dqs/) and complete the registration procedure. After you register an account, go to [this](https://portal.spamhaustech.com/src/manual/dqs/) page and note the DQS key.

# Installation instructions

## Prerequisites

You naturally need a DQS key along with Spamassassin 3.4.1+ already installed on your system. These instructions do not cover the initial Spamassassin installation. 
To correctly install Spamassassin please refer to instructions applicable to your distribution.

The scores in this configuration files are weighted for a `required_score` of 4 instead of the default 6. If you use a different `required_score` adjust the values accordingly.

## Conventions

We are going to use some abbreviations and placeholders:

 * SA: SpamAssassin
 * SH: Spamhaus
 * *configuration directory*: whenever you'll find these italic words, we will refer to SA's configuration directory. Depending on your distribution it may be `/etc/spamassassin` or `/etc/mail/spamassassin` or other
 * whenever you find the box below, it means that you need to enter the command on your shell.
```
	# command
``` 

## Installation instructions

* Download the [latest SA-SH package (20190621)](https://docs.spamhaustech.com/_static/software/SA-spamhaus.tgz) into any directory of your choice

* Extract it by giving

```
	# tar xvfz SA-spamhaus.tgz
```

A subdirectory called `SA-spamhaus-20190621` will be created. Within it, besides licensing information, you will find three files:

 * `SH.pm`. This is a dedicated SA plugin written by SH that overcomes some of SA's limitations
 * `sh.cf`. This file contains lookup redefinitions and will need to be edited (see below)
 * `sh_scores.cf`. In this file we override some of SA's default rule scoring

* Make a copy of these files into the SA *configuration directory* (it may require root privileges).

Now, assuming your DQS key is for instance `aip7yig6sahg6ehsohn5shco3z`, execute the following command inside the *configuration directory*

```
	# sed -i -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' sh.cf
```

There will be no output, but your key will be placed inside `sh.cf` in all the needed places.

Finally, edit `sh.cf` with your editor of choice, and take a look at the first line:

```
loadplugin       Mail::SpamAssassin::Plugin::SH <config_directory\>/SH.pm
```

You will need to replace `<config_directory\>` with your actual *configuration directory*. So, for example, if your *configuration directory* is `/etc/mail/spamassassin`, the line will become:

```
loadplugin       Mail::SpamAssassin::Plugin::SH /etc/mail/spamassassin/SH.pm
```

Now test the setup by running:

```
	# spamassassin --lint
```
	
This command checks the whole SA installation; if you don't see any output then congratulations! You successfully installed SH's SA setup.

## Plugin internals

While we undoubtedly recognize Spamassassin's abilities at stopping spam with only minor tweakings to the default config, there are some key uses of our datasets that can be fully taken advantage of only by writing some special SA functions. This is why we decided to develop this special plugin that includes these functions:

 * `check_sh_helo`.
This function checks the domain used in the HELO/EHLO string against DBL and ZRD.

 * `check_sh_headers`. 
This function takes the domain out of the *From* , *Reply-to* , *Envelope From*, *Return-Path* header lines and then checks the domain against DBL and ZRD.

 * `check_sh_body`.
This function scans the email body looking for email addresses. For all email addresses found, it extracts the domain and check it against DBL and ZRD. This approach has been proven useful, for example, in some dating scams campaign.

 * `check_sh_reverse`
This function checks the reverse DNS (rDNS) of the last untrusted relay in both DBL and ZRD

 * `check_sh_bodyuri_a`
 This function scans the email body and looks for URLs; when one is found the hostname is then resolved and the resulting IP address is checked in SBL and CSS

## Final recommendations

The configuration in the VBSpam survey makes use exclusively of our data, as our goal was certifying their quality and keep an eye on how we perform in the field. So, malware is blocked using just IP addresses and domain real-time data.

While the results are reasonably good, the malware/phishing scoring can certainly be improved through some additional actions that we recommend.

Nowadays the rule of thumb for receiving email should be to stay defensive, that is why we recommend to do basic attachment filtering by dropping all emails that contains potentially hazardous attachments, like *at least* all file extensions that match this regex:

```
(exe|vbs|pif|scr|bat|cmd|com|cpl|dll|cpgz|chm|js|jar|wsf)
```

You should also drop, by default, all Office documents with macros.

The second recommendation is to run an AV (Anti-Virus) engine on your server, to scan all mail attachments. This can be easily done with SpamAssassin, using the AV product of your choice.
