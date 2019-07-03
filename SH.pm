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

# version 20190703

package Mail::SpamAssassin::Plugin::SH;

use strict;
use warnings;

use Net::DNS;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;
use List::MoreUtils qw(uniq);
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

sub _get_domains_from_body_emails {
  my ($self,$pms,$bodyref) = @_;
  my $body = join('', @{$bodyref});
  my @address_list;
  my @domains;
  foreach my $this_address (uniq( $body =~ /\b([\w\d\_\-\+\.]+\@(?:[\w\d\-]+\.)+[\w\d\-]{2,10})\b/g )) { push @address_list, lc $this_address; }
  @address_list = uniq(@address_list);
  foreach my $this_address (@address_list) {
    my ($this_user, $this_domain )       = split('@', $this_address);
    $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($this_domain);
    dbg("SHPlugin: (_get_domains_from_body_emails) found domain ".$this_domain." in email ".$this_address." found in body");
    push @domains, $this_domain
  }
  @domains = uniq(@domains);
  return (@domains);
}

sub _get_headers_domains {
  my ($self,$pms) = @_;
  my @domains;
  if (defined($pms->get( 'From:addr' ))) {
    my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($pms->get( 'From:addr' ));
    dbg("SHPlugin: (_get_headers_domains) found domain ".$this_domain." in From:addr");
    push @domains, $this_domain;
  }
  if (defined($pms->get( 'Reply-To:addr' ))) {
    my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($pms->get( 'Reply-To:addr' ));
    dbg("SHPlugin: (_get_headers_domains) found domain ".$this_domain." in Reply-To:addr");
    push @domains, $this_domain;
  }
  if (defined($pms->get( 'Sender:addr' ))) {
    my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($pms->get( 'Sender:addr' ));
    dbg("SHPlugin: (_get_headers_domains) found domain ".$this_domain." in Sender:addr");
    push @domains, $this_domain;
  }
  if (defined($pms->get( 'EnvelopeFrom:addr' ))) {
    my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($pms->get( 'EnvelopeFrom:addr' ));
    dbg("SHPlugin: (_get_headers_domains) found domain ".$this_domain." in EnvelopeFrom:addr");
    push @domains, $this_domain;
  }
  if (defined($pms->get( 'Return-Path:addr' ))) {
    my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($pms->get( 'Return-Path:addr' ));
    dbg("SHPlugin: (_get_headers_domains) found domain ".$this_domain." in Return-Path:addr");
    push @domains, $this_domain;
  }
  @domains = uniq(@domains);
  @domains = grep /\S/, @domains;
  return (@domains);
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
  my (@domains) = _get_domains_from_body_emails($self,$pms,$bodyref);
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
  my (@domains) = _get_domains_from_body_emails($self,$pms,$bodyref);
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
  foreach my $this_hostname (uniq( $body =~ /[a-z][a-z0-9+\-.]*:\/\/(?:[a-z0-9\-._~%!$&'()*+,;=]+@)?([a-z0-9\-._~%]+|↵\[[a-z0-9\-._~%!$&'()*+,;=:]+\])/g)) { push @uris, lc $this_hostname; }
  @uris = uniq(@uris);
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
  foreach my $this_hostname (uniq( $body =~ /[a-z][a-z0-9+\-.]*:\/\/(?:[a-z0-9\-._~%!$&'()*+,;=]+@)?([a-z0-9\-._~%]+|↵\[[a-z0-9\-._~%!$&'()*+,;=:]+\])/g)) { push @uris, lc $this_hostname; }
  @uris = uniq(@uris);
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

