As many MDaemon (https://www.altn.com) administrators know, MDaemon uses SpamAssassin as the antispam service. 

Through some tinkering we've been able to make our plugin works with MDaemon too, and what follows are the instructions on how to do it. 

**DISCLAIMER**

We've been able to have the plugin correctly installed and some of our customers confirms that it's indeed working on their production sites. However, this is not a procedure supported by MDaemon, so use these instructions at your own risk.

This procedure has only been tested with MDaemon 21.5.2 that bundles SpamAssassin 3.4.4. It should work with all other releases that use a SpamAssassin version >= 3.4.1

**END DISCLAIMER**

First of all, from the MDaemon server, download the latest .zip with the code from here: https://github.com/spamhaus/spamassassin-dqs/archive/refs/heads/master.zip

You'll end up with a file called "spamassassin-dqs-master.zip"

Unzip the file and you'll have the following files ready:

![unzipped](https://user-images.githubusercontent.com/52405319/164720200-787068d3-a274-41c4-b39c-429e1f50ac5a.png)

Now, we are assuming you have MDaemon installed in the default "C:\MDaemon" directory. If you have it somewhere else please replace all the references to "C:\MDaemon" with your actual directory.

All file editing should *not* be done with Notepad, because it doesn't correctly understand UNIX CR/LFs. Notepad++, Wordpad, Word, Sublime Text are to be preferred.

Copy "SH.pm" and "sh.pre" in the "C:\MDaemon\SpamAssassin\default_rules" directory.

Open the sh.pre file with a text editor, and replace the first line at the top from
```
loadplugin      Mail::SpamAssassin::Plugin::SH <config_directory>/SH.pm
```
to
```
loadplugin      Mail::SpamAssassin::Plugin::SH C:\MDaemon\SpamAssassin\default_rules\SH.pm
```
Open the "sh.cf" file with a text editor and, with the built-in "Find/Replace" function, replace *all* the occurrences of the string "your_DQS_key" with *your* DQS key. In Wordpad it looks like this:

![replace](https://user-images.githubusercontent.com/52405319/164720449-cb4b583e-c4bd-402f-8834-03876ea1a17f.png)

Of course you need to use *your* key and not the one shown in the screenshot.

Once you did that, do the same for the "sh_hbl.cf" file.

If you DQS key is HBL enabled (all paying customers have the DQS key HBL enabled), copy "sh.cf", "sh_hbl.cf", "sh_scores.cf" and "sh_hbl_scores.cf" in C:\MDaemon\SpamAssassin\rules

If you are a free user and your key is not HBL enabled, copy "sh.cf", and "sh_scores.cf" in C:\MDaemon\SpamAssassin\rules

Now stop the "AntiSpam" service from the MDaemon admin interface (Main -> Status)

![rS0Z1LiS7Wy5sGwE](https://user-images.githubusercontent.com/52405319/164720664-bd013c98-132e-4b5c-b4e4-1f9dfc7229cd.png)

Go to C:\MDaemon\SpamAssassin\rules and *MAKE A BACKUP COPY* of the "Local.cf" file. Once you backed it up, open "Local.cf" file with an editor, and add the following line at the end:
```
envelope_sender_header X-Envelope-From
```
Also look for the line that reads:
```
skip_rbl_checks 1
```
and change it to:
```
skip_rbl_checks 0
```
If you already have:
```
skip_rbl_checks 0
```
Then you don't need to change anything else.

Restart the AntiSpam service and you should be good to go! Try to send/receive some emails to confirm the the mail flow is still intact and enjoy the increased catch rate :)

If anything goes wrong, you can restore the original situation by replacing the "Local.cf" file with the version that you backed up, and deleting the various files copied in the two "rules" directories.
