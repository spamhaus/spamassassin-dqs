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
use Digest::SHA qw(sha256 );

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
  # Finds Cryptowallets in the body and check if hey are being used in spam campaigns
  $self->register_eval_rule ( 'check_sh_crypto' );
  # Check attachment's hashes
  $self->register_eval_rule ( 'check_sh_attachment' );
  # Check email hashes
  $self->register_eval_rule ( 'check_sh_emails' );
  # Finds URIs in the email body and checks their hostnames
  $self->register_eval_rule ( 'check_sh_hostname' );
  return $self;
}

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

sub finish_parsing_end {
  my ($self, $opts) = @_;

  return 0 if !$self->{sh_available};

  # valid_tlds_re will be available at finish_parsing_end, compile it now,
  # we only need to do it once and before possible forking
  if (!exists $self->{email_regex}) {
    $self->_init_email_re();
  }
  return 0;
}

sub _init_email_re {
  my ($self) = @_;
  my $sa_version = Mail::SpamAssassin::Version();
  $sa_version =~ tr/\.//d;
  $sa_version = substr $sa_version, 0, 3;
  # This is an ugly hack to make the regex work with SA 3.4.1 and possibly 3.4.0. Not recommended as TLDs are not updated
  # dinamically like in 3.4.2 where they are updated via sa-update
  if ($sa_version < 342) {
    $self->{main}->{registryboundaries}->{valid_tlds_re} = '(?^i:(?:education|ch|watch|coffee|bo|fr|capital|et|yandex|yachts|ag|kh|es|events|gmail|systems|by|xn--3e0b707e|land|global|nl|xn--lgbbat1ad8j|kim|vi|no|gop|lgbt|cz|ni|gifts|xn--c1avg|praxi|sl|consulting|uk|xn--mgberp4a5d4ar|hm|za|kitchen|xn--wgbh1c|xn--45brj9c|xn--3bst00m|fo|mn|xn--p1ai|co|camera|voto|gw|actor|is|berlin|sa|kn|ovh|care|int|joburg|audio|shoes|cab|uy|schmidt|ceo|auction|pg|wed|neustar|xn--6frz82g|vote|reisen|company|gi|cat|vacations|xn--fzc2c9e2c|ong|onl|us|ng|cy|li|church|pr|ac|life|sz|xn--4gbrim|wang|top|tatar|ls|exposed|expert|pw|marketing|nu|py|cn|gl|cologne|sv|cr|mortgage|tirol|brussels|guitars|ad|nr|vlaanderen|eg|blackfriday|fishing|xn--czru2d|gp|xn--vhquv|xn--fpcrj9c3d|country|press|international|re|coop|nagoya|physio|cc|cleaning|rs|voyage|juegos|sy|mp|xn--fiq228c5hs|xn--nqv7fs00ema|social|er|city|recipes|ck|st|kw|healthcare|computer|koeln|hk|bnpparibas|industries|paris|university|sarl|host|xn--cg4bki|cd|diet|org|xn--ses554g|vodka|td|sn|day|lt|tokyo|rich|diamonds|gt|credit|club|qpon|gb|sm|xn--io0a7i|xn--6qq986b3xl|ge|cl|ink|nz|bargains|kz|hiv|mz|menu|sh|xn--o3cw4h|jo|post|xn--80adxhks|lighting|id|nc|plumbing|nrw|np|sd|uz|arpa|tl|clinic|photography|bio|pizza|ninja|website|il|tz|pm|tm|tv|restaurant|associates|sj|scb|organic|bb|equipment|gratis|boutique|enterprises|mx|foundation|xn--80ao21a|dentist|xn--l1acc|navy|christmas|democrat|villas|in|gbiz|fi|futbol|name|gu|xn--j6w193g|meet|ne|ventures|net|technology|vc|mk|photos|cancerresearch|bzh|xn--h2brj9c|financial|dnp|xn--90a3ac|tax|cv|estate|tj|cern|sohu|horse|gg|fitness|xn--mgbc0a9azcg|whoswho|camp|am|nra|condos|beer|kr|uno|institute|construction|dental|tattoo|accountants|ua|xyz|bv|zw|im|academy|fish|ru|quebec|mt|nhk|gm|gf|autos|me|suzuki|tools|ma|mango|ai|republican|ky|tw|flights|gq|rocks|md|black|boo|az|meme|bd|bi|hu|xn--pgbs0dh|ar|xn--ngbc5azd|durban|mobi|xxx|sexy|jobs|ae|cash|at|youtube|citic|tf|okinawa|ie|network|pf|domains|scot|support|london|rodeo|zone|nyc|pt|ws|sb|holiday|versicherung|productions|tk|vu|limo|br|maison|frogans|space|xn--i1b6b1a6a2e|xn--xkc2al3hye2a|au|xn--rhqv96g|works|wales|edu|miami|active|eu|pa|cruises|soy|furniture|xn--mgbx4cd0ab|ms|mini|gives|toys|lease|ing|hn|bike|eus|place|finance|vet|gmo|degree|sg|gov|io|software|reviews|motorcycles|vegas|bmw|immo|homes|xn--unup4y|mo|builders|green|xn--q9jyb4c|jp|sr|feedback|repair|lc|rentals|gift|info|pl|florist|archi|rest|bid|caravan|pub|tg|xn--zfr164b|fj|red|xn--mgbayh7gpa|business|gd|supplies|ro|otsuka|tienda|cards|wien|direct|exchange|xn--kprw13d|om|gn|mw|ye|pink|digital|deals|ca|ph|ve|bn|attorney|museum|xn--gecrj9c|ci|so|moscow|bt|glass|gy|dad|mg|gripe|dm|ao|cu|guide|tt|sk|dj|cheap|guru|xn--fiq64b|mh|jetzt|luxury|haus|email|catering|bg|cf|ec|partners|aq|ruhr|tr|cool|xn--ygbi2ammx|gal|xn--xhq521b|xn--ogbpf8fl|my|tn|bj|xn--mgba3a4f16a|vn|lk|xn--nqv7f|lb|yokohama|aero|xn--mgb9awbf|dz|al|properties|kaufen|aw|wiki|fund|gh|property|pe|com|ba|loans|tips|here|xn--80asehdb|spiegel|lr|krd|ir|na|hamburg|la|luxe|mc|airforce|ps|gr|iq|house|sx|hosting|bz|schule|uol|cw|af|pro|training|cg|community|as|se|kred|clothing|xn--yfro4i67o|mil|ryukyu|bw|blue|best|media|hiphop|it|build|contractors|zm|holdings|nf|rsvp|bayern|esq|cooking|dk|bs|ly|ga|gent|help|foo|xn--j1amh|directory|ug|gs|monash|mov|today|kg|ren|asia|desi|xn--fiqz9s|pn|va|ke|bm|fm|si|solar|capetown|viajes|eat|surf|ee|be|km|career|pictures|lv|dating|ngo|army|reise|cuisinella|xn--mgbbh1a71e|wf|supply|an|xn--55qw42g|insure|xn--1qqw23a|sc|pk|graphics|dance|voting|tel|center|su|lacaixa|xn--fiqs8s|bf|singles|xn--s9brj9c|frl|trade|de|mq|ht|realtor|moe|parts|mm|cm|pics|bh|xn--wgbl6a|gallery|college|engineer|farm|new|photo|services|rehab|rw|moda|xn--xkc2dl3a5ee0h|lu|report|xn--clchc0ea0b2g2a9gcd|je|kp|fail|management|cymru|ooo|tc|webcam|codes|xn--80aswg|ml|rio|qa|buzz|careers|agency|vg|fk|ax|engineering|axa|immobilien|limited|lotto|lawyer|xn--3ds443g|ki|xn--czr694b|investments|solutions|mr|travel|prod|cx|williamhill|to|surgery|hr|creditcard|xn--kput3i|market|mu|xn--kpry57d|vision|bar|xn--mgbaam7a8h|discount|biz|saarland|wtc|claims|xn--55qx5d|mv|xn--mgbab2bd|wtf|yt|link|globo|how|melbourne|kiwi|xn--d1acj3b|shiksha|town|ltda|th|do|jm|sca|click))';
    dbg("SHPlugin: Email regex hack for SA < 3.4.2 engaged. Consider switching to 3.4.2+");
  }
  # Some regexp tips courtesy of http://www.regular-expressions.info/email.html
  # full email regex v0.02
  if ($sa_version < 343) {
    # Add the "make sure domain ends here" code to prevent "example.com"
    # from being wrongly parsed as "example.co" (this code is already present
    # in SpamAssassin 3.4.3)
    $self->{email_regex} = qr/
      (?=.{0,64}\@)                       # limit userpart to 64 chars (and speed up searching?)
      (?<![a-z0-9!#\$%&'*+\/=?^_`{|}~-])  # start boundary
      (                                   # capture email
      [a-z0-9!#\$%&'*+\/=?^_`{|}~-]+      # no dot in beginning
      (?:\.[a-z0-9!#\$%&'*+\/=?^_`{|}~-]+)* # no consecutive dots, no ending dot
      \@
      (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
      $self->{main}->{registryboundaries}->{valid_tlds_re} # ends with valid tld
      )
      (?!(?:[a-z0-9-]|\.[a-z0-9]))      # make sure domain ends here
    /xi;
  } else {
    $self->{email_regex} = qr/
      (?=.{0,64}\@)                       # limit userpart to 64 chars (and speed up searching?)
      (?<![a-z0-9!#\$%&'*+\/=?^_`{|}~-])  # start boundary
      (                                   # capture email
      [a-z0-9!#\$%&'*+\/=?^_`{|}~-]+      # no dot in beginning
      (?:\.[a-z0-9!#\$%&'*+\/=?^_`{|}~-]+)* # no consecutive dots, no ending dot
      \@
      (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
      $self->{main}->{registryboundaries}->{valid_tlds_re} # ends with valid tld
      )
    /xi;
  }
# lazy man debug
#open(my $fh, '>', "/tmp/reg") or die "Could not open file $!";
#print $fh $self->{email_regex};
#close $fh;
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
  my %seen;
  my @uris;
  my @parsed = $pms->get_uri_list(); 
  foreach ( @parsed ) {
    my ($domain, $host) = $self->{main}->{registryboundaries}->uri_to_domain($_);
    if ( $host ) { 
      push (@uris, lc $host) unless defined $seen{lc $host};
      $seen{lc $host} = 1;
    }
  }
  foreach my $this_uri (@uris) {
    dbg("SHPlugin: (_get_body_uris) found  ".$this_uri." in body");
  }
  return (@uris);
}

sub _get_part_details {
  my ($pms, $part) = @_;
  #https://en.wikipedia.org/wiki/MIME#Content-Disposition
  #https://github.com/mikel/mail/pull/464
  my $ctt = $part->get_header('content-type');
  return undef unless defined $ctt;
  my $cte = lc($part->get_header('content-transfer-encoding') || '');
  return undef unless ($cte =~ /^(?:base64|quoted\-printable)$/);
  $ctt = _decode_part_header($part, $ctt || '');
  my $name = '';
  my $cttname = '';
  my $ctdname = '';
  if($ctt =~ m/(?:file)?name\s*=\s*["']?([^"';]*)["']?/is){
    $cttname = $1;
    $cttname =~ s/\s+$//;
  }
  my $ctd = $part->get_header('content-disposition');
  $ctd = _decode_part_header($part, $ctd || '');
  if($ctd =~ m/filename\s*=\s*["']?([^"';]*)["']?/is){
    $ctdname = $1;
    $ctdname =~ s/\s+$//;
  }
  if (lc $ctdname eq lc $cttname) {
    $name = $ctdname;
  } elsif ($ctdname eq '') {
    $name = $cttname;
  } elsif ($cttname eq '') {
    $name = $ctdname;
  } else {
    if ($pms->{conf}->{olemacro_prefer_contentdisposition}) {
      $name = $ctdname;
    } else {
      $name = $cttname;
    }
  }
  return $ctt, $ctd, $cte, lc $name;
}

sub _decode_part_header {
  my($part, $header_field_body) = @_;
  return '' unless defined $header_field_body && $header_field_body ne '';
  # deal with folding and cream the newlines and such
  $header_field_body =~ s/\n[ \t]+/\n /g;
  $header_field_body =~ s/\015?\012//gs;
  local($1,$2,$3);
  # Multiple encoded sections must ignore the interim whitespace.
  # To avoid possible FPs with (\s+(?==\?))?, look for the whole RE
  # separated by whitespace.
  1 while $header_field_body =~
            s{ ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) \s+
               ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) }
             {$1$2}xsg;
  # transcode properly encoded RFC 2047 substrings into UTF-8 octets,
  # leave everything else unchanged as it is supposed to be UTF-8 (RFC 6532)
  # or plain US-ASCII
  $header_field_body =~
    s{ (?: = \? ([A-Za-z0-9_-]+) \? ([bqBQ]) \? ([^?]*) \? = ) }
     { $part->__decode_header($1, uc($2), $3) }xsge;
  return $header_field_body;
}

sub _get_full_body_uris {
  my ($self,$pms, $bodyref) = @_;
  my $body = join('', @{$bodyref});    
  my %seen;
  my @uris;
  foreach my $this_uri ( $body =~ /([a-zA-Z][a-zA-Z0-9+\-.]*:\/\/(?:[a-zA-Z0-9\-._~%!$&'()*+,;=]+@)?[a-zA-Z0-9\-._~%\/]+)/g) { 
    push (@uris, lc $this_uri) unless defined $seen{lc $this_uri};
    $seen{lc $this_uri} = 1;
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

sub _get_body_emails {
  my ($self,$pms) = @_;
  # This extraction code has been heavily copypasted and slightly adapted from https://github.com/smfreegard/HashBL/blob/master/HashBL.pm
  my %seen;
  my @body_emails;
  # get all <a href="mailto:", since they don't show up on stripped_body
  my $parsed = $pms->get_uri_detail_list();
  while (my($uri, $info) = each %{$parsed}) {
    if (defined $info->{types}->{a} and not defined $info->{types}->{parsed}) {
      if ($uri =~ /^(?:(?i)mailto):$self->{email_regex}/) {
        my $this_email = lc($1);
        push(@body_emails, $this_email) unless defined $seen{$this_email};
        $seen{$this_email} = 1;
        last if scalar @body_emails >= 20; # sanity
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
      my $this_email = lc($1);
      push(@body_emails, $this_email) unless defined $seen{$this_email};
      $seen{$this_email} = 1;
      last BODY if scalar @body_emails >= 40; # sanity
    }
  }
  foreach my $this_email (@body_emails) {
    dbg("SHPlugin: (_get_body_emails) found email ".$this_email." in body");
  }
  return (@body_emails);
}

sub _get_headers_domains {
  my ($self,$pms) = @_;
  # This extraction code has been heavily copypasted and slightly adapted from https://github.com/smfreegard/HashBL/blob/master/HashBL.pm
  my %seen;
  my @headers_domains;
  my @headers = ('EnvelopeFrom', 'Sender', 'From', 'Reply-To', 'Resent-Sender','X-Envelope-From','Return-Path');
  foreach my $header (@headers) {
    if ($pms->get($header . ':addr')) {
      my $this_domain = $self->{'main'}->{'registryboundaries'}->uri_to_domain($pms->get( $header.':addr' ));
      if ($this_domain) {
        dbg("SHPlugin: (_get_headers_domains) found domain ".$this_domain." in header ".$header);
        push(@headers_domains, $this_domain) unless defined $seen{$this_domain};
        $seen{$this_domain} = 1;
      }
    }
  }
  return (@headers_domains);
}

sub _get_headers_emails {
  my ($self,$pms) = @_;
  # This extraction code has been heavily copypasted and slightly adapted from https://github.com/smfreegard/HashBL/blob/master/HashBL.pm
  my %seen;
  my @headers_emails;
  my @headers = ('EnvelopeFrom', 'Sender', 'From', 'Reply-To', 'Resent-Sender','X-Envelope-From','Return-Path');
  foreach my $header (@headers) {
    my $email = lc($pms->get($header . ':addr'));
    if ($email) {
        dbg("SHPlugin: (_get_headers_emails) found email ".$email." in header ".$header);
        push(@headers_emails, $email) unless defined $seen{$email};
        $seen{$email} = 1;
    }
  }
  return (@headers_emails);
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
  if (@header_domains) {
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
  }
  return 0;
}

sub check_sh_emails {

  my ($self, $pms, $list, $subtest) = @_;

  return 0 unless $self->{sh_available};
  return 0 unless defined $list;

  my $conf = $pms->{conf};
  my $skip_domains = $conf->{sh_emailbl_skip_domains};
  $skip_domains = {}  if !$skip_domains;
  my @header_emails;
  my @body_emails;
  my @emails;
  (@header_emails) = _get_headers_emails($self,$pms);
  (@body_emails) = _get_body_emails($self,$pms);
  push(@emails,@body_emails);
  push(@emails,@header_emails);
  my $rulename = $pms->get_current_eval_rule_name();
  if (@emails) {
    foreach my $email (@emails) {
      # Normalize googlemail.com -> gmail.com
      $email =~ s/\@googlemail\.com/\@gmail\.com/;
      # Remove plus sign if present
      $email =~ s/(\+.*\@)/@/;
      my ($this_user, $this_domain )       = split('@', $email);
      if ($this_domain && !($skip_domains->{$this_domain})) {
	# Remove dots from left part if rightpart is gmail.com
        if ($email =~ /\@gmail\.com/) {
          $this_user =~ s/(\.)//g;
          $email = $this_user.'@'.$this_domain;
        }
        my $hash = encode_base32(sha256($email));
        my $lookup = $hash.".".$list;
        my $key = "SH:$lookup";
        my $ent = {
          key => $key,
          zone => $list,
          type => 'SH',
          rulename => $rulename,
          addr => "$email",
        };
        $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
          my ($ent, $pkt) = @_;
          $self->_finish_lookup($pms, $ent, $pkt, $subtest);
        }, master_deadline => $pms->{master_deadline});
      } 
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
          dbg("SHPlugin: (check_sh_headers_ns) found authoritative NS for %s: %s", $this_domain, $rr_ns->nsdname);
          $self->lookup_a_record($pms, $rr_ns->nsdname, $list, $rulename, $subtest);
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
          dbg("SHPlugin: (check_sh_bodyemail_ns) found authoritative NS for %s: %s", $this_domain, $rr_ns->nsdname);
          $self->lookup_a_record($pms, $rr_ns->nsdname, $list, $rulename, $subtest);
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
      dbg("SHPlugin: (check_sh_bodyuri_a) lookup_a_record for URI ".$this_hostname);
      $self->lookup_a_record($pms, $this_hostname, $list, $rulename, $subtest);
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
          dbg("SHPlugin: (check_sh_bodyuri_ns) found authoritative NS for %s: %s", $this_domain, $rr_ns->nsdname);
          $self->lookup_a_record($pms, $rr_ns->nsdname, $list, $rulename, $subtest);
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
    if ((substr $rdns, -1) eq ".") { chop $rdns; }
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

sub check_sh_crypto {
  my ($self, $pms, $bodyref, $list, $subtest, $cr, $cryptovalue) = @_;
  my $regex = qr/$cr/;
  return 0 unless $self->{sh_available};
  return 0 unless defined $list;
  my %addrs;
  my $body = join('', @{$bodyref});
  dbg("SHPlugin: looking for $cryptovalue addresses...");
  while ($body =~ /($regex)/g) {
    $addrs{$1} = 1;
    dbg("SHPlugin: Found possible crypto $cryptovalue address $1");
    last if keys %addrs >= 10; # max unique
  }
  if (!%addrs) {
    dbg("SHPlugin: no crypto addresses found");
    return 0;
  }
  my $rulename = $pms->get_current_eval_rule_name();
  foreach my $addr (keys %addrs) {
    my $hash = encode_base32(sha256($addr));
    dbg("SHPlugin: Crypto address '$addr' of type $cryptovalue found in body, checking against $list ($hash)");
    my $lookup = "$hash.$list";
    my $key = "SH:$lookup";
    my $ent = {
        key => $key,
        zone => $list,
        type => 'SH',
        rulename => $rulename,
        addr => $addr,
        hash => $hash,
    };
    $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
      my ($ent, $pkt) = @_;
      $self->_finish_lookup($pms, $ent, $pkt, $subtest);
    }, master_deadline => $pms->{master_deadline});
  }
}

sub check_sh_attachment {
  my ($self,$pms,$body,$list,$subtest) = @_;
  my $rulename = $pms->get_current_eval_rule_name();
  foreach my $part ($pms->{msg}->find_parts(qr/./, 1, 1)) {
    my ($ctt, $ctd, $cte, $name) = _get_part_details($pms, $part);
    next unless defined $ctt;
    my $hash = encode_base32(sha256($part->decode()));
    dbg("SHPlugin: (check_sh_attachment) Found file $name with hash $hash");
    my $lookup = "$hash.$list";
    my $key = "SH:$lookup";
    my $ent = {
        key => $key,
        zone => $list,
        type => 'SH',
        rulename => $rulename,
        addr => $hash,
        hash => $hash,
    };
    $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
      my ($ent, $pkt) = @_;
      $self->_finish_lookup($pms, $ent, $pkt, $subtest);
    }, master_deadline => $pms->{master_deadline});
  }
  return 0;
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

1;

