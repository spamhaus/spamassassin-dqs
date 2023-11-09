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

# version 20220420

package Mail::SpamAssassin::Plugin::SH;

use strict;
use warnings;

use Net::DNS;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;
use Socket;
use Mail::SpamAssassin::Logger;
use Digest::SHA qw(sha256 sha1_hex);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new( $mailsa );
  bless ($self, $class);
  $self->set_config($mailsa->{conf});
  my $sa_version_full = Mail::SpamAssassin::Version();
  my $sa_version = $sa_version_full;
  $sa_version =~ tr/\.//d;
  $sa_version = substr $sa_version, 0, 3;
  if ($sa_version < 341) {
   print("\nSHPlugin: ************************** WARNING *************************\n");
   print("SHPlugin: This plugin will work only with SpamAssassin 3.4.1 and above\n");
   print("SHPlugin: Your currently installed version is $sa_version_full\n");
   print("SHPlugin: ******************** THIS WILL NOT WORK ********************\n");
   print("SHPlugin: Remove sh.pre file or update SpamAssassin\n\n");
   die();
  }
  # are network tests enabled?
  if ($mailsa->{local_tests_only}) {
    $self->{sh_available} = 0;
    $self->{URIHash_available} = 0;
    dbg("SHPlugin: local tests only, disabled");
  } else {
    $self->{sh_available} = 1;
    $self->{URIHash_available} = 1;
  }

  # URIHASH part, borrowed from SURBL
  $self->register_eval_rule ( 'check_urihash' );
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
sub _finish_lookup {
  my ($self, $pms, $ent, $pkt,$subtest) = @_;
  my $re;
  return if !$pkt;
  dbg("SHPlugin: _finish_lookup on $ent->{addr} / $ent->{rulename} / $subtest");
  if (!($subtest)) { $re = qr/^127\./; } else { $re = qr/$subtest/; }
  my @answer = $pkt->answer;
  foreach my $rr (@answer) {
    if ($rr->address =~ /$re/) {
      dbg("SHPlugin: Hit on Item $ent->{addr} for $ent->{rulename}");
      $pms->test_log($ent->{addr});
      $pms->got_hit($ent->{rulename}, '', ruletype => 'eval');
      return;
    }
  }
}

# ---------------------------------------------------------------------------

sub lookup_a_record {
        my ($self, $pms, $hname, $list, $rulename, $subtest) = @_;

        my $key = "A:" . $hname;
        my $ent = {
                key => $key,
                zone => $list,
                type => "SH",
                rulename => $rulename,
        };
        dbg("SHPlugin: launching lookup for $hname on $list");
        $pms->{async}->bgsend_and_start_lookup(
                $hname, 'A', undef, $ent,
                sub {
                        my ($ent2,$pkt) = @_;
                        $self->continue_a_record_lookup($pms, $ent2, $pkt, $hname, $rulename, $subtest)
                        }, master_deadline => $pms->{master_deadline} );
}

sub continue_a_record_lookup
{
        my ($self, $pms, $ent, $pkt, $hname, $rulename, $subtest) = @_;

        if (!$pkt)
        {
                # $pkt will be undef if the DNS query was aborted (e.g. timed out)
                dbg("SHPlugin: continue_a_record_lookup aborted %s", $hname);
                return;
        }
        dbg("SHPlugin: continue_a_record_lookup reached for %s", $hname);

        my @answer = $pkt->answer;
        foreach my $rr (@answer)
        {
                if ($rr->type eq 'A')
                {
                        my $ip_address = $rr->rdatastr;
                        dbg("SHPlugin: continue_a_record_lookup found A record for URI ".$hname.": ".$ip_address);
                        my $reversed = join ".", reverse split /[.]/, $ip_address;
                        my $lookup = $reversed.".".$ent->{zone};
                        my $key = "SH:$lookup";
                        my $ent2 = {
                                key => $key,
                                zone => $ent->{zone},
                                type => 'SH',
                                addr => $ip_address,
                                rulename => $rulename,
                                };
                        $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent2, sub {
                                my ($ent3, $pkt) = @_;
                                $self->_finish_lookup($pms, $ent3, $pkt, $subtest);
                                }, master_deadline => $pms->{master_deadline});
                }
        }
}

sub encode_base32 {
    my $arg = shift;
    return '' unless defined($arg);    # mimic MIME::Base64

    $arg = unpack('B*', $arg);
    $arg =~ s/(.....)/000$1/g;
    my $l = length($arg);
    if ($l & 7) {
        my $e = substr($arg, $l & ~7);
        $arg = substr($arg, 0, $l & ~7);
        $arg .= "000$e" . '0' x (5 - length $e);
    }
    $arg = pack('B*', $arg);
    $arg =~ tr|\0-\37|A-Z2-7|;
    return $arg;
}

sub parse_config {
    my ($self, $opts) = @_;

    if ($opts->{key} =~ /^urihash_acl_([a-z0-9]{1,32})$/i) {
        $self->inhibit_further_callbacks();
        return 1 unless $self->{URIHash_available};

        my $acl = lc($1);
        foreach my $temp (split(/\s+/, $opts->{value}))
        {
            if ($temp =~ /^([a-z0-9._\/-]+)$/i) {
#            if ($temp =~ /^([a-z0-9._\/-\.\*]+)$/i) {
                my $domain = lc($1);
                $domain =~ s/\./\\./g;
                push @{$self->{urihash_domains}{$acl}}, $domain;
            }
            else {
                warn("SHPlugin (URIHASH) invalid acl: $temp");
            }
        }
        if ($acl eq 'all') {
          dbg("Pushing default ACL");
          push @{$self->{urihash_domains}{$acl}}, "(?:https?:\/\/(.*?))";
#last          push @{$self->{urihash_domains}{$acl}}, "(?:https?:\\/\\/).*";
#          push @{$self->{urihash_domains}{$acl}}, "(:?https?:\\/\\/(?:.+:.+@)?).*";
        }


        return 1;
    }
    elsif ($opts->{key} =~ /^urihash_path_([a-z0-9]{1,32})$/i) {
        $self->inhibit_further_callbacks();
        return 1 unless $self->{URIHash_available};

        my $acl = lc($1);
        eval { qr/$opts->{value}/; };
        if ($@) {
            warn("SHPlugin (URIHASH) invalid path regex for $acl: $@");
            return 0;
        }
        $self->{urihash_path}{$acl} = $opts->{value};

        return 1;
    }

    return 0;
}

sub finish_parsing_end {
    my ($self, $opts) = @_;

    return 0 unless $self->{URIHash_available};

    foreach my $acl (keys %{$self->{urihash_domains}}) {
        unless (defined $self->{urihash_path}{$acl}) {
            warn("SHPlugin (URIHASH) missing urihash_path_$acl definition");
            next;
        }
        my $restr;
        $restr = '(?<![a-z0-9.-])'.
                    '('.join('|', @{$self->{urihash_domains}{$acl}}).')'.
                    '('.$self->{urihash_path}{$acl}.')';
        if ($acl eq "all") {
           $restr = '(?<![a-z0-9.-])'.
           '(?:https?:\/\/(.*?))'.
           '('.$self->{urihash_path}{$acl}.')';
        }

        my $re = eval { qr/$restr/i; };
        if ($@) {
            warn("SHPlugin (URIHASH) invalid regex for $acl: $@");
            next;
        }
        dbg("re: $re");
        $self->{urihash_re}{$acl} = $re;
    }

    my $recnt = scalar keys %{$self->{urihash_re}};
    dbg("loaded $recnt acls");

    return 0;
}

# parse eval rule args
sub _parse_args {
    my ($self, $acl, $zone, $zone_match) = @_;

    if (not defined $zone) {
        warn("SHPlugin (URIHASH) acl and zone must be specified for rule");
        return ();
    }
    # acl
    $acl =~ s/\s+//g; $acl = lc($acl);
    if ($acl !~ /^[a-z0-9]{1,32}$/) {
        warn("SHPlugin (URIHASH) invalid acl definition: $acl");
        return ();
    }
    if ($acl ne 'all' and not defined $self->{urihash_re}{$acl}) {
        warn("SHPlugin (URIHASH) no such acl defined: $acl");
        return ();
    }
    if ($acl eq 'all') {
        dbg("SHPlugin (URIHASH) \"all\" acl defined");
    }

    # zone
    $zone =~ s/\s+//g; $zone = lc($zone);
    unless ($zone =~ /^[a-z0-9_.-]+$/) {
        warn("SHPlugin (URIHASH) invalid zone definition: $zone");
        return ();
    }

    # zone_match
    if (defined $zone_match) {
        my $tst = eval { qr/$zone_match/ };
        if ($@) {
            warn("SHPlugin (URIHASH) invalid match regex: $zone_match");
            return ();
        }
    }
    else {
        $zone_match = '127\.\d+\.\d+\.\d+';
    }
    return ($acl, $zone, $zone_match);
}

sub _add_desc {
    my ($self, $pms, $uri, $desc) = @_;

    my $rulename = $pms->get_current_eval_rule_name();
    if (not defined $pms->{conf}->{descriptions}->{$rulename}) {
        $pms->{conf}->{descriptions}->{$rulename} = $desc;
    }
    if ($pms->{main}->{conf}->{urihash_add_describe_uri}) {
        #$email =~ s/\@/[at]/g; TODO
        $pms->{conf}->{descriptions}->{$rulename} .= " ($uri)";
    }
}
                                                
# hash and lookup array of uris
sub _lookup {
    my ($self, $pms, $prs, $uris) = @_;

#    return 0 unless defined @$uris;
    return 0 unless @$uris;

    my %digests = map { sha1_hex($_) => $_ } @$uris;
    my $dcnt = scalar keys %digests;

    # nothing to do?
    return 0 unless $dcnt;

    # todo async lookup and proper timeout
    my $timeout = int(10 / $dcnt);
    $timeout = 3 if $timeout < 3;

    my $resolver = Net::DNS::Resolver->new(
        udp_timeout => $timeout,
        tcp_timeout => $timeout,
        retrans => 0,
        retry => 1,
        persistent_tcp => 0,
        persistent_udp => 0,
        dnsrch => 0,
        defnames => 0,
    );
    foreach my $digest (keys %digests) {
        my $uri = $digests{$digest};
        my $clean_uri = $uri;
        $clean_uri =~ /(.*?)\//;
        if (($prs->{acl} ne "all") && ($1 ne "")) {
          $pms->{urihash_lookup_cache}{"$1"} = 'cached';
        } else {
           if ((defined $1) && (defined $pms->{urihash_lookup_cache}{"$1"})) { next; }
        }
        # if cached
        if (defined $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"}) {
            my $addr = $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"};
            dbg("lookup: $digest.$prs->{zone} ($uri) [cached]");
            return 0 if ($addr eq '');
            if ($addr =~ $prs->{zone_match}) {
                dbg("HIT! $digest.$prs->{zone} = $addr ($uri)");
                $self->_add_desc($pms, $uri, "URIHash hit at ");
                return 1;
            }
            return 0;
        }

        dbg("lookup: $digest.$prs->{zone} ($uri)");
        my $query = $resolver->query("$digest.$prs->{zone}", 'A');
        if (not defined $query) {
            if ($resolver->errorstring ne 'NOERROR' &&
                $resolver->errorstring ne 'NXDOMAIN') {
                dbg("DNS error? ($resolver->{errorstring})");
            }
            $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"} = 'cached';
            next;
        }
        foreach my $rr ($query->answer) {
            if ($rr->type ne 'A') {
                dbg("got answer of wrong type? ($rr->{type})");
                next;
            }
            if (defined $rr->address && $rr->address ne '') {
                $pms->{urihash_lookup_cache}{"$digest.$prs->{zone}"} = $rr->address;
                if ($rr->address =~ $prs->{zone_match}) {
                    dbg("HIT! $digest.$prs->{zone} = $rr->{address} ($uri)");
                    $self->_add_desc($pms, $uri, "URIHash hit at ");
                    return 1;
                }
                else {
                    dbg("got answer, but not matching $prs->{zone_match} ($rr->{address})");
                }
            }
            else {
                dbg("got answer but no IP? ($resolver->{errorstring})");
            }
        }
    }

    return 0;
}

sub _urihash {
    my ($self, $pms, $acl, $zone, $zone_match) = @_;

    my $prs = {}; # per rule state
    $prs->{acl} = $acl;
    $prs->{zone} = $zone;
    $prs->{zone_match} = $zone_match;
    $prs->{rulename} = $pms->get_current_eval_rule_name();

    dbg("RULE ($prs->{rulename}) acl:$acl zone:$zone match:${zone_match}");
    my %uris;

    my $parsed = $pms->get_uri_detail_list();
    while (my($uri, $info) = each %{$parsed}) {
        if (defined $info->{types}->{a} and not defined $info->{types}->{parsed}) {
            if ($uri =~ $self->{urihash_re}{$acl}) {
                my $domain = lc($1);
                my $path = $2;
                $path =~ s/%([a-f0-9]{2})/chr(hex($1))/eig;
                $uris{"$domain$path"} = 1;
                last if scalar keys %uris >= 3;
            }
        }
    }

    my $body = $pms->get_decoded_body_text_array();
    BODY: foreach (@$body) {
        while (/$self->{urihash_re}{$acl}/g) {
            my $final_dom;
            my $path = $2;
            $final_dom = $1;
            if ($acl eq "all") {
#             $final_dom =~ s/https?:\/\/(?:.+:.+@)?//;
              $final_dom =~ /https?:\/\/((?:.+:.+@)?.*?)\//;
              $final_dom = $1;
              $path = lc($path);
#             $path = "";
            }
            my $domain = lc($final_dom);
            $path =~ s/%([a-f0-9]{2})/chr(hex($1))/eig;
            $uris{"$domain$path"} = 1;
            last BODY if scalar keys %uris >= 12;
        }
    }
    my @lookups = keys %uris;
    return $self->_lookup($pms, $prs, \@lookups);
}

sub check_urihash {
    my ($self, $pms, @args) = @_;

#    shift @args;

    return 0 unless $self->{URIHash_available};
    return 0 unless (@args = $self->_parse_args(@args));
    return _urihash($self, $pms, @args);
}





1;

