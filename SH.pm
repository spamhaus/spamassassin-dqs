# <@LICENSE>
# Copyright 2019 Spamhaus Technology Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

# The Spamhaus Technology SpamAssassin development crew can be reached
# at <spamassassin at spamteq.com> for questions/suggestions related
# with this plug-in exclusively.

# version 20190704

package Mail::SpamAssassin::Plugin::SH;

use strict;
use warnings;

use Net::DNS;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;
use Socket;
use Mail::SpamAssassin::Logger;


our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new( $mailsa );
  bless ($self, $class);
  $self->set_config($mailsa->{conf});
  # are network tests enabled?
  if ($mailsa->{local_tests_only}) {
    $self->{sh_available} = 0;
    dbg("SHPlugin: local tests only, disabled");
  } else {
    $self->{sh_available} = 1;
  }
  # Finds email in the email body and check their @domains
  $self->register_eval_rule ( 'check_sh_bodyemail' );
  # Finds email in the email body and check their @domain's authoritative name servers IPs
  $self->register_eval_rule ( 'check_sh_bodyemail_ns' );
  # Checks envelope and body headers (Return-Path, From, Reply-To etc..) @domains
  $self->register_eval_rule ( 'check_sh_headers' );
  # Checks envelope and body headers (Return-Path, From, Reply-To etc..) @domains's authoritative name servers IPs
  $self->register_eval_rule ( 'check_sh_headers_ns' );
  # Checks the HELO string
  $self->register_eval_rule ( 'check_sh_helo' );
  # Checks the reverse DNS of the last untrusted relay
  $self->register_eval_rule ( 'check_sh_reverse' );
  # Finds URIs in the email body and checks their corresponding A record
  $self->register_eval_rule ( 'check_sh_bodyuri_a' );
  # Finds URIs in the email body and checks their domain's authoritative name servers IPs
  $self->register_eval_rule ( 'check_sh_bodyuri_ns' );

  # Taken from https://github.com/smfreegard/HashBL/blob/master/HashBL.pm
  $self->{email_regex} = qr/
    (?=.{0,64}\@)				# limit userpart to 64 chars (and speed up searching?)
    (?<![a-z0-9!#\$%&'*+\/=?^_`{|}~-])	# start boundary
    (						# capture email
    [a-z0-9!#\$%&'*+\/=?^_`{|}~-]+		# no dot in beginning
    (?:\.[a-z0-9!#\$%&'*+\/=?^_`{|}~-]+)*	# no consecutive dots, no ending dot
    \@
    (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
    $self->{main}->{registryboundaries}->{valid_tlds_re}	# ends with valid tld
    )
    (?!(?:[a-z0-9-]|\.[a-z0-9]))		# make sure domain ends here
  /xi;

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'uridnsbl_skip_domain',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{uridnsbl_skip_domains}->{lc $domain} = 1;
      }
    }
  });

}

sub _get_body_uris {
  my ($self,$pms, $bodyref) = @_;
  my $body = join('', @{$bodyref});    
  my %seen;
  my @uris;
  foreach my $this_uri ( $body =~ /[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/(?:[a-zA-Z0-9\-._~%!$&'()*+,;=]+@)?([a-zA-Z0-9\-._~%]+|↵\[[a-zA-Z0-9\-._~%!$&'()*+,;=:]+\])/g) { 
    push (@uris, lc $this_uri) unless defined $seen{lc $this_uri};
    $seen{lc $this_uri} = 1;
  }
  foreach my $this_uri (@uris) {
    dbg("SHPlugin: (_get_body_uris) found  ".$this_uri." in body");
  }

  return (@uris);
}

sub _get_domains_from_body_emails {
  my ($self,$pms) = @_;
  # This extraction code has been heavily copypasted and slightly adapted from https://github.com/smfreegard/HashBL/blob/master/HashBL.pm
  my %seen;
  my @body_domains;
  # get all <a href="mailto:", since they don't show up on stripped_body
  my $parsed = $pms->get_uri_detail_list();
  while (my($uri, $info) = each %{$parsed}) {
    if (defined $info->{types}->{a} and not defined $info->{types}->{parsed}) {
      if ($uri =~ /^(?:(?i)mailto):$self->{email_regex}/) {
        my $email = lc($1);
        my ($this_user, $this_domain )       = split('@', $email);
        push(@body_domains, $this_domain) unless defined $seen{$this_domain};
        $seen{$this_domain} = 1;
        last if scalar @body_domains >= 20; # sanity
      }
    }
  }
  # scan stripped normalized body
  # have to do this way since get_uri_detail_list doesn't know what mails are inside <>
  my $body = $pms->get_decoded_stripped_body_text_array();
  BODY: foreach (@$body) {
    # strip urls with possible emails inside
    s#<?https?://\S{0,255}(?:\@|%40)\S{0,255}# #gi;
    # strip emails contained in <>, not mailto:
    # also strip ones followed by quote-like "wrote:" (but not fax: and tel: etc)
    s#<?(?<!mailto:)$self->{email_regex}(?:>|\s{1,10}(?!(?:fa(?:x|csi)|tel|phone|e?-?mail))[a-z]{2,11}:)# #gi;
    while (/$self->{email_regex}/g) {
      my $email = lc($1);
      my ($this_user, $this_domain )       = split('@', $email);
      push(@body_domains, $this_domain) unless defined $seen{$this_domain};
      $seen{$this_domain} = 1;
      last BODY if scalar @body_domains >= 40; # sanity
    }
  }
  foreach my $this_domain (@body_domains) {
    dbg("SHPlugin: (_get_domains_from_body_emails) found domain ".$this_domain." in body email");
  }
  return (@body_domains);
}

sub _get_headers_domains {
  my ($self,$pms) = @_;
  # This extraction code has been heavily copypasted and slightly adapted from https://github.com/smfreegard/HashBL/blob/master/HashBL.pm
  my %seen;
  my @headers_domains;
  my @headers = ('EnvelopeFrom', 'Sender', 'From', 'Reply-To');
  foreach my $header (@headers) {
    if ($pms->get($header . ':addr')) {
      my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($pms->get( $header.':addr' ));
      dbg("SHPlugin: (_get_headers_domains) found domain ".$this_domain." in header ".$header);
      push(@headers_domains, $this_domain) unless defined $seen{$this_domain};
      $seen{$this_domain} = 1;
    }
  }
  return (@headers_domains);
}

sub check_sh_headers {

  my ($self, $pms, $list, $subtest) = @_;

  return 0 unless $self->{sh_available};
  return 0 unless defined $list;

  my $conf = $pms->{conf};
  my $skip_domains = $conf->{uridnsbl_skip_domains};
  $skip_domains = {}  if !$skip_domains;
  my @header_domains;

  (@header_domains) = _get_headers_domains($self,$pms);

  my $rulename = $pms->get_current_eval_rule_name();
  foreach my $this_domain (@header_domains) {
    if (!($skip_domains->{$this_domain})) {
      my $lookup = $this_domain.".".$list;
      my $key = "SH:$lookup";
      my $ent = {
        key => $key,
        zone => $list,
        type => 'SH',
        rulename => $rulename,
        addr => $this_domain,
      };
      $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
        my ($ent, $pkt) = @_;
        $self->_finish_lookup($pms, $ent, $pkt, $subtest);
      }, master_deadline => $pms->{master_deadline});
    }
  }
  return 0;
}

sub check_sh_headers_ns {

  my ($self, $pms, $list, $subtest) = @_;

  return 0 unless $self->{sh_available};
  return 0 unless defined $list;

  my $conf = $pms->{conf};
  my $skip_domains = $conf->{uridnsbl_skip_domains};
  $skip_domains = {}  if !$skip_domains;

  my @headers_domains;

  (@headers_domains) = _get_headers_domains($self,$pms);
  my $rulename = $pms->get_current_eval_rule_name();

  foreach my $this_domain (@headers_domains) {
    if (!($skip_domains->{$this_domain})) {
      dbg("SHPlugin: (check_sh_headers_ns) checking authoritative NS for domain ".$this_domain);
      my $res   = Net::DNS::Resolver->new;
      $res->udp_timeout(3);
      $res->tcp_timeout(3);
      my $reply_ns = $res->query("$this_domain", "NS");
      if ($reply_ns) {
        foreach my $rr_ns (grep { $_->type eq "NS" } $reply_ns->answer) {
          my @addresses = gethostbyname($rr_ns->nsdname);
          @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];
          foreach my $address (@addresses) {
            dbg("SHPlugin: (check_sh_headers_ns) found authoritative NS for domain ".$this_domain.": ".$rr_ns->nsdname."->".$address);
            my $result = join ".", reverse split /[.]/, $address;
            my $lookup = $result.".".$list;
            my $key = "SH:$lookup";
            my $ent = {
              key => $key,
              zone => $list,
              type => 'SH',
              rulename => $rulename,
              addr => $result,
            };
            $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
             my ($ent, $pkt) = @_;
             $self->_finish_lookup($pms, $ent, $pkt, $subtest);
            }, master_deadline => $pms->{master_deadline});
         } 
       } 
      }
    }     
  }
  return 0;
}

sub check_sh_helo {

  my ($self, $pms, $list, $subtest) = @_;

  return 0 unless $self->{sh_available};
  return 0 unless defined $list;

  my $conf = $pms->{conf};
  my $skip_domains = $conf->{uridnsbl_skip_domains};
  $skip_domains = {}  if !$skip_domains;

  my $rulename = $pms->get_current_eval_rule_name();

  my $lasthop = $pms->{relays_untrusted}->[0];
  if (!defined $lasthop) {
    dbg ("SHPlugin: message was delivered entirely via trusted relays, not required");
    return;
  }

  my $helo = $lasthop->{helo};
  if (!($skip_domains->{$helo})) {
    dbg ("SHPlugin: (check_sh_helo) checking HELO (helo=$helo)");
    my $lookup = $helo.".".$list;
    my $key = "SH:$lookup";
    my $ent = {
      key => $key,
      zone => $list,
      type => 'SH',
      rulename => $rulename,
      addr => $helo,
    };
    $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
      my ($ent, $pkt) = @_;
      $self->_finish_lookup($pms, $ent, $pkt, $subtest);
    }, master_deadline => $pms->{master_deadline});
  }
  return 0;
}

sub check_sh_bodyemail_ns {

  my ($self, $pms, $bodyref, $list, $subtest) = @_;

  return 0 unless $self->{sh_available};
  return 0 unless defined $list;

  my $conf = $pms->{conf};
  my $skip_domains = $conf->{uridnsbl_skip_domains};
  $skip_domains = {}  if !$skip_domains;
  my $rulename = $pms->get_current_eval_rule_name();
  my (@domains) = _get_domains_from_body_emails($self,$pms);
  foreach my $this_domain (@domains) {
    if (!($skip_domains->{$this_domain})) {
      dbg("SHPlugin: (check_sh_bodyemail_ns) checking authoritative NS for domain ".$this_domain);
      my $res   = Net::DNS::Resolver->new;
      $res->udp_timeout(3);
      $res->tcp_timeout(3);
      my $reply_ns = $res->query("$this_domain", "NS");
      if ($reply_ns) {
        foreach my $rr_ns (grep { $_->type eq "NS" } $reply_ns->answer) {
          my @addresses = gethostbyname($rr_ns->nsdname);
          @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];
          foreach my $address (@addresses) {
            dbg("SHPlugin: (check_sh_bodyemail_ns) found authoritative NS for domain ".$this_domain.": ".$rr_ns->nsdname."->".$address);
            my $result = join ".", reverse split /[.]/, $address;
            my $lookup = $result.".".$list;
            my $key = "SH:$lookup";
            my $ent = {
              key => $key,
              zone => $list,
              type => 'SH',
              rulename => $rulename,
              addr => $result,
            };
            $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
             my ($ent, $pkt) = @_;
             $self->_finish_lookup($pms, $ent, $pkt, $subtest);
            }, master_deadline => $pms->{master_deadline});
         }
       }
      } 
    }
  }
  return 0;
}

sub check_sh_bodyemail {

  my ($self, $pms, $bodyref, $list, $subtest) = @_;

  return 0 unless $self->{sh_available};
  return 0 unless defined $list;

  my $conf = $pms->{conf};
  my $skip_domains = $conf->{uridnsbl_skip_domains};
  $skip_domains = {}  if !$skip_domains;
  my $rulename = $pms->get_current_eval_rule_name();
  my (@domains) = _get_domains_from_body_emails($self,$pms);
  foreach my $this_domain (@domains) {
    if (!($skip_domains->{$this_domain})) {
      dbg("SHPlugin: (check_sh_bodyemail) checking body domain ".$this_domain);
      my $lookup = $this_domain.".".$list;
      my $key = "SH:$lookup";
      my $ent = {
        key => $key,
        zone => $list,
        type => 'SH',
        rulename => $rulename,
        addr => $this_domain,
      };
      $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
        my ($ent, $pkt) = @_;
        $self->_finish_lookup($pms, $ent, $pkt, $subtest);
      }, master_deadline => $pms->{master_deadline});
    }
  }
  return 0;
}

sub check_sh_bodyuri_a {

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
      my @addresses = gethostbyname($this_hostname);
      @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];
      foreach my $address (@addresses) { 
        my $result = join ".", reverse split /[.]/, $address;
        dbg("SHPlugin: (check_sh_bodyuri_a) Found A record for URI ".$this_hostname.": ".$address);
        my $lookup = $result.".".$list;
        my $key = "SH:$lookup";
        my $ent = {
          key => $key,
          zone => $list,
          type => 'SH',
          rulename => $rulename,
          addr => $result,
        };
          $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
            my ($ent, $pkt) = @_;
            $self->_finish_lookup($pms, $ent, $pkt, $subtest);
        }, master_deadline => $pms->{master_deadline});
          #   return (check_rbl($result, $list, $subtest));
      }
    } 
  }
  return 0;
}

sub check_sh_bodyuri_ns {

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
    my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($this_hostname);
    if (!($skip_domains->{$this_hostname})) {
      dbg("SHPlugin: (check_sh_bodyuri_ns) checking authoritative NS for domain ".$this_domain." from URI ".$this_hostname." found in body");
      my $res   = Net::DNS::Resolver->new;
      $res->udp_timeout(3);
      $res->tcp_timeout(3);
      my $reply_ns = $res->query("$this_domain", "NS");
      if ($reply_ns) {
        foreach my $rr_ns (grep { $_->type eq "NS" } $reply_ns->answer) {
          my @addresses = gethostbyname($rr_ns->nsdname);
          @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];
          foreach my $address (@addresses) {
            dbg("SHPlugin: (check_sh_bodyuri_ns) found authoritative NS for domain ".$this_domain.": ".$rr_ns->nsdname."->".$address);
            my $result = join ".", reverse split /[.]/, $address;
            my $lookup = $result.".".$list;
            my $key = "SH:$lookup";
            my $ent = {
              key => $key,
              zone => $list,
              type => 'SH',
              rulename => $rulename,
              addr => $result,
            };
            $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
             my ($ent, $pkt) = @_;
             $self->_finish_lookup($pms, $ent, $pkt, $subtest);
            }, master_deadline => $pms->{master_deadline});
          }
        }
      }
    } 
  }
  return 0;
}

sub check_sh_reverse {

  my ($self, $pms, $list, $subtest) = @_;

  return 0 unless $self->{sh_available};
  return 0 unless defined $list;

  my $rulename = $pms->get_current_eval_rule_name();

  my $lasthop = $pms->{relays_untrusted}->[0];
  if (!defined $lasthop) {
    dbg ("SHPlugin: message was delivered entirely via trusted relays, not required");
    return;
  }

  my $rdns = $lasthop->{rdns};
  if ($rdns) {
    dbg ("SHPlugin: (check_sh_reverse) checking RDNS of the last untrusted relay (rdns=$rdns)");

    my $lookup = $rdns.".".$list;
    my $key = "SH:$lookup";
    my $ent = {
      key => $key,
      zone => $list,
      type => 'SH',
      rulename => $rulename,
      addr => $rdns,
    };
    $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
      my ($ent, $pkt) = @_;
      $self->_finish_lookup($pms, $ent, $pkt, $subtest);
    }, master_deadline => $pms->{master_deadline});
    return 0;
  }
}

sub _finish_lookup {
  my ($self, $pms, $ent, $pkt,$subtest) = @_;
  my $re;
  return if !$pkt;
  if (!($subtest)) { $re = qr/^127\./; } else { $re = qr/$subtest/; }
  my @answer = $pkt->answer;
  foreach my $rr (@answer) {
#    if ($rr->address =~ /^127\./) {
    if ($rr->address =~ /$re/) {
      dbg("SHPlugin: Hit on Item $ent->{addr} for $ent->{rulename}");
      $pms->test_log($ent->{addr});
      $pms->got_hit($ent->{rulename}, '', ruletype => 'eval');
      return;
    }
  }
}

1;

