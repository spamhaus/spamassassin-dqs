**Instructions for SpamAssassin users**

These instructions will help you participate in the beta testing of the new Spamhaus DBL with hostnames. More informations about the changes that are being introduced can be found here: https://www.spamhaus.com/resource-center/hostnames-for-spamhaus-domain-blocklist/

To use the beta version of the Spamhaus Domain Blocklist (DBL) with hostnames, all you need to do is install the DQS plugin, following the instructions found here: https://github.com/spamhaus/spamassassin-dqs, and make a few simple changes to the code, as detailed below:

Edit the 'SH.pm' file and insert additional code, it's full path is likely to be either `/etc/mail/spamassassin/SH.pm` or `/etc/spamassassin/SH.pm`:

 Around line 84 you'll find this block of code

	# Check email hashes
	$self->register_eval_rule ( 'check_sh_emails' );
	
You need to add the two following lines

	  # Finds URIs in the email body and checks their hostnames
	  $self->register_eval_rule ( 'check_sh_hostname' );

The updated version now looks like

	  # Check email hashes
	  $self->register_eval_rule ( 'check_sh_emails' );
	  # Finds URIs in the email body and checks their hostnames
	  $self->register_eval_rule ( 'check_sh_hostname' );
	
A few lines down you'll see a block of code that starts with

	sub log_syslog {
	 my ($priority, $msg) = @_;	
	 ...
	 
Paste the following block of code before that function

	sub check_sh_hostname {
	
	  my ($self, $pms, $bodyref, $list, $subtest) = @_;
	  my $conf = $pms->{conf};
	  return 0 unless $self->{sh_available};
	  return 0 unless defined $list;
	
	  my $skip_domains = $conf->{uridnsbl_skip_domains};
	  $skip_domains = {}  if !$skip_domains;
	
	  my $body = join('', @{$bodyref});
	  my $rulename = $pms->get_current_eval_rule_name();
	
	  my @uris;
	  (@uris) = _get_body_uris($self,$pms,$bodyref);
	
	  foreach my $this_hostname (@uris) {
	    if (!($skip_domains->{$this_hostname})) {
	      dbg("SHPlugin: (check_sh_hostname) checking ".$this_hostname);
	      my $lookup = $this_hostname.".".$list;
	      my $key = "SH:$lookup";
	      my $ent = {
	        key => $key,
	        zone => $list,
	        type => 'SH',
	        rulename => $rulename,
	        addr => $this_hostname,
	      };
	      $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
	        my ($ent, $pkt) = @_;
	        $self->_finish_lookup($pms, $ent, $pkt, $subtest);
	      }, master_deadline => $pms->{master_deadline});
	    }
	  }
	  return 0;
	}

Edit the `sh.cf` file. It's full path is probably `/etc/mail/spamassassin/sh.cf` or `/etc/spamassassin/sh.cf`. 

Go to the end of the file, and before the final line of the file:

	endif # Mail::SpamAssassin::Plugin::SH
	
add the following lines

	  body          SH_DBL_ABUSED_FULLHOST  eval:check_sh_hostname('dbl-beta.spamhaus.org', '^127\.0\.1\.10[2-6]$')
	  priority      SH_DBL_ABUSED_FULLHOST  -100
	  describe      SH_DBL_ABUSED_FULLHOST  A hostname found in the email body is listed in DBL as abused_legit
	
Edit the `sh_scores.cf`file'. It's full path is probably `/etc/mail/spamassassin/sh_scores.cf` or `/etc/spamassassin/sh_scores.cf. 
	1. Go at the end of the file, and just before the line that ends the file

	endif # Mail::SpamAssassin::Plugin::SH

add the following line

	  score SH_DBL_ABUSED_FULLHOST  6

You are done! Just run `$ spamassassin --lint` and check that there are no errors in the output.
