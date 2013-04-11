#!/usr/bin/env perl
use strict;
use Getopt::Long;
use Try::Tiny;
use YAML qw/Dump DumpFile Load LoadFile/;
use POSIX ":sys_wait_h";
use Storable qw( freeze thaw );
use IO::Interface::Simple;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use IPC::ShareLite qw( :lock );;

$| = 1; # need autoflush in order to make tail working

my $DEBUG = 1 if $ENV{PCAPSTATS_DEBUG} == 1;

my $stats = {};
my ($err, $dev, $config_file, $conf, $interval, @pcap_filters, @wanted_stats, $my_ip, @children, @shares );


GetOptions(
    "config=s"      => \$config_file,
    "device=s"      => \$dev,
    "interval=i"    => \$interval,
    "filter=s"      => \@pcap_filters,
    "stats=s"       => \@wanted_stats,
    "my_ip=s"       => \$my_ip,
    "help"          => \my $help
);


if ( defined $config_file and -f $config_file ){
    $conf = LoadFile( $config_file );
    my $i = 1;
    while ( my $f = shift @{ $conf->{ filters } } ){
        push( @pcap_filters, $f->{ pcap } );
        while ( my $s = shift @{ $f->{ stats } } ){
            push( @wanted_stats, "$i.$s" );
        }
        $i++;
    }
}

usage() unless ($dev and @pcap_filters and @wanted_stats) or defined $config_file;
usage() if $help;

sub usage{
    unless ( $help ){
        warn "No device provided (--device)\n" unless $dev;
        warn "No filters provided (--filters)\n" unless @pcap_filters;
        warn "No stats provided (--stats)\n" unless @wanted_stats;
    }

    print "$0 --d|device=s [--i|interval=60] --f|filter=s [--f|filter=s ...] --s|stats=s [--s|stats=s ...]\n";
    print "output: \n";
    print "\tfilter_index,timestamp,rx(1.stats_1),tx(1.stats_1),rx(1.stats_2),tx(1.stats_2)...\n";
    print "\tfilter_index begins at 1.\n";

    exit 1 unless $help;
    exit 0;
}

$interval ||= 60;

print "interval can't be equal to zero.\n" unless $interval;
exit 1 unless $interval;

### Get my ip
my $if = IO::Interface::Simple->new( $dev );
$my_ip ||= $if->address;
print "My ip: $my_ip\n";

print "Capturing packets on $dev, print pcap stats every $interval secs.\n";

sub alrm{
    # here we print the current statistics
    &time_elapsed;
    # we will schedule the next print of statistics 
    alarm $interval;
};
local $SIG{ALRM} = \&alrm;

sub sig{
    #do nothing for now
}
local $SIG{CHLD} = \&sig;

$SIG{PIPE} = \&sig;

sub sigint{
    for ( @children ){
        # kill TERM
        kill 15,$_;
        warn "$$ kill $_" if $DEBUG;
    }
    alarm 0;
}

sub time_elapsed {
    print "\n$$ " . Dump ($stats) if $DEBUG;

    my $time = time ;
    # $share->lock( LOCK_EX );

    for ( my $f_num = 1; $f_num <= @children ; $f_num++ ){
        while ( 1 ){
            $stats = thaw( $shares[ $f_num ]->fetch );
            last if $stats;
        }
        my @out = ( $time );
        for my $ws ( grep{ /^$f_num\./ } @wanted_stats ){

            for ( split(',', $ws ) ){
                /([a-zA-Z]+)\(?([0-9a-zA-Z_ =.-]+)?\)?/;
                if ( $1 eq 'bw' or $1 eq 'throughput' ){
                    push( @out, $stats->{ $f_num }->{ rx }->{ bw }->{ count } == 0 ?
                        0
                        :
                        ($stats->{ $f_num }->{ rx }->{ bw }->{ bytes } / $stats->{ $f_num }->{ rx }->{ bw }->{ count }) / $interval );
                    push( @out, $stats->{ $f_num }->{ tx }->{ bw }->{ count } == 0 ? 
                        0
                        :
                        ($stats->{ $f_num }->{ tx }->{ bw }->{ bytes } / $stats->{ $f_num }->{ tx }->{ bw }->{ count }) / $interval );
                }
                else{
                    push ( @out, $stats->{ $f_num }->{ rx }->{ $2 }->{ $1 } );
                    push ( @out, $stats->{ $f_num }->{ tx }->{ $2 }->{ $1 } );
                }
            }
        }
        print $f_num , "," , join(',', @out ) , "\n";
        undef @out;
    }
    for ( @children ){
        # we send signal to all children to make them reset the statistics that need to be set to 0 before gathering statisctis for the next interval
        kill 1, $_;
    }
    # $share->unlock;
}

sub master {
    my ( $pid, $forks ) = @_;
    push ( @children, $pid );
    warn "w $pid pushed" if $DEBUG;
    if ( $forks == 0 ){

        local $SIG{INT} = \&sigint;
        print "CSV output headers:\n";
        for ( my $f_num = 1; $f_num <= @children ; $f_num++ ){
            print "filter_number($f_num),timestamp,", join(',', ( 
                map { 
                    /^$f_num\.(.+)/;
                    my @ret;
                    for ( split(',', $1) ){ 
                        push( @ret, ( "$_.rx", "$_.tx" ) );
                    }
                    @ret;
                } grep { /^$f_num\./; } @wanted_stats ) ) , "\n";
        }
        alarm $interval;
        for ( @children ){
            waitpid -1, 0;
        }
        warn "master $$ ending"if $DEBUG;
        undef $_ for @shares;
        undef @shares;
    }
}

sub child {
    my $f_num = shift;
    my ($address, $netmask, $object, $time_elapsed );

    use POSIX qw(SIGTERM SIGHUP);

    POSIX::sigaction('SIGTERM', POSIX::SigAction->new(sub { 
        print "$$ is exiting TERM...\n"; Net::Pcap::breakloop($object); sleep 1; Net::Pcap::close($object); #IPC::Shareable->clean_up; 
        exit 0;
    })) || die "Error setting SIGTERM handler: $!\n";
    POSIX::sigaction('SIGHUP', POSIX::SigAction->new(sub { 
        # it"s time to reset if you need
        $time_elapsed = 1;
    })) || die "Error setting SIGHUP handler: $!\n";

    if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
        die 'Unable to look up device information for ', $dev, ' - ', $err;
    }
    try{
        #$share->lock( LOCK_EX );
        $stats = thaw( $shares[ $f_num ]->fetch );
        for my $ws ( grep { /^$f_num\./ } @wanted_stats ){
            for ( split(',', $ws ) ){
                /([a-zA-Z]+)\(?([0-9a-zA-Z_ =.-]+)?\)?/;
                if ( $1 eq 'bw' or $1 eq 'throughput' ){
                    $stats->{ $f_num }->{ rx }->{ bw }->{ bytes } = 0;
                    $stats->{ $f_num }->{ tx }->{ bw }->{ bytes } = 0; 
                    $stats->{ $f_num }->{ rx }->{ bw }->{ count } = 0;
                    $stats->{ $f_num }->{ tx }->{ bw }->{ count } = 0; 
                }
                else{
                    $stats->{ $f_num }->{ rx }->{ $2 }->{ $1 } = 0;
                    $stats->{ $f_num }->{ tx }->{ $2 }->{ $1 } = 0;                    
                }
            }
            # if ( $ws =~ /\.(bw|throughput)/ ){
            #     $stats->{ $f_num }->{ rx }->{ bw }->{ bytes } = 0;
            #     $stats->{ $f_num }->{ tx }->{ bw }->{ bytes } = 0;
            #     $stats->{ $f_num }->{ rx }->{ bw }->{ count } = 0;
            #     $stats->{ $f_num }->{ tx }->{ bw }->{ count } = 0;
            # }
        }

        $shares[ $f_num ]->store( freeze( $stats ) );
        #$share->unlock;

        #   Create packet capture object on device
        $object = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);
        unless (defined $object) {
            die 'Unable to create packet capture on device ', $dev, ' - ', $err;
        }

        my $filter;
        # print "Filter number $f_num: '". $pcap_filters[$f_num - 1] ."', stats: '". join(', ', ( grep { /^$f_num\./; } @wanted_stats ) ) . "'\n";
        Net::Pcap::compile(
            $object, 
            \$filter, 
            $pcap_filters[$f_num - 1], 
            0, 
            $netmask
        ) && die 'Unable to compile packet capture filter:' . $pcap_filters[$f_num - 1];

        Net::Pcap::setfilter($object, $filter) &&
            die 'Unable to set packet capture filter';

        #   Set callback function and initiate packet capture loop

        Net::Pcap::loop($object, -1, \&process_packet, $f_num ) ||
            die 'Unable to perform packet capture';

        Net::Pcap::close($object);

    } catch {
        warn DumpFile ("/tmp/pcapstats-$$", $_ );
        die $_;
    };

    sub process_packet {
        my ( $f_num, $header, $packet ) = @_;
        my $ether_data = NetPacket::Ethernet::strip($packet);
        warn "$$ $f_num ", Dump $stats if $DEBUG;

        my $ip = NetPacket::IP->decode($ether_data);
        
        my $updated = 0;
        # while ( ! $updated ){

            #if ( $share->lock( LOCK_EX ) ){

                # $stats = thaw( $shares[ $f_num ]->fetch( ));
                if ( $time_elapsed ){
                    if ( exists $stats->{ $f_num }->{ rx }->{ bw } ){
                        $stats->{ $f_num }->{ rx }->{ bw }->{ bytes } = 0;
                        $stats->{ $f_num }->{ rx }->{ bw }->{ count } = 0;
                    }
                    if ( exists $stats->{ $f_num }->{ tx }->{ bw } ){
                        $stats->{ $f_num }->{ tx }->{ bw }->{ bytes } = 0;
                        $stats->{ $f_num }->{ tx }->{ bw }->{ count } = 0;
                    }
                    $time_elapsed = 0;
                }

                $stats->{ $f_num }->{ last_update } = time;
                if ( $ip->{ dest_ip } == $my_ip ){
                    &stat_function( $stats->{ $f_num }->{ rx }, $header, $packet, $ether_data, $ip );
                }
                else{
                    &stat_function( $stats->{ $f_num }->{ tx }, $header, $packet, $ether_data, $ip );
                }

                $shares[ $f_num ]->store( freeze( $stats ) );
                # $share->unlock;

                $updated = 1;
            # }
        # }
    }

    sub stat_function{
        my ($stats, $header, $packet, $ether_data, $ip) = @_;

        warn "$$ $f_num ", Dump $stats if $DEBUG;
        for my $field ( keys %{ $stats } ){
            if ( $field eq 'bw' ){
                $stats->{ $field }->{ bytes } += $header->{ len };
                $stats->{ $field }->{ count }++;
                next;
            }
            for my $function ( keys %{ $stats->{ $field } } ){
                if ( $function eq 'cum' ){
                    if ( $field eq 'len' ) {
                        $stats->{ $field }->{ $function } += $header->{ len };
                    }
                }
                elsif( $function eq 'count'){
                    $field =~ /([a-zA-Z ]+)\s*=\s*(.+)/;
                    my $f_name = $1;
                    my $f_value = $2;
                    if ( $f_name eq 'len' ) {
                        $stats->{ $field }->{ count }++ if $header->{ $f_name } eq $f_value;
                    }elsif ( $f_name eq 'dst' ) {
                        $stats->{ $field }->{ count }++ if $ip->{ dest_ip } eq $f_value;
                    }elsif ( $f_name eq 'src' ){
                        $stats->{ $field }->{ count }++ if $ip->{ src_ip } eq $f_value;
                    }elsif( $f_name eq 'host' ){
                        $stats->{ $field }->{ count }++ if $ip->{ src_ip } eq $f_value;
                        $stats->{ $field }->{ count }++ if $ip->{ dest_ip } eq $f_value;
                    }elsif ( $f_name =~ /^(dst|src)?\s*port$/i ) {
                        my $type = $1;
                        my $tcp = NetPacket::TCP->decode( $ip->{'data'} );
                        $stats->{ $field }->{ count }++ if $type eq 'dst' and $tcp->{ dest_port } eq $f_value;
                        $stats->{ $field }->{ count }++ if $type eq 'src' and $tcp->{ src_port } eq $f_value;
                        $stats->{ $field }->{ count }++ unless $type;

                    }
                }
            }
        }
    }
}


unless (defined $dev) {
    $dev = Net::Pcap::lookupdev(\$err);
    if (defined $err) {
        die 'Unable to determine network device for monitoring - ', $err;
    }
}

my $filter_number;

### Forks
my $forks = @pcap_filters;
warn "forks = $forks" if $DEBUG;

while ( $forks-- ) {
    $filter_number++;
    # Forks and returns the pid for the child:

    ### Prepare shared memory segments for child'stats
    $shares[ $filter_number ] = IPC::ShareLite->new(
        -key     => "pf$filter_number",
        -mode    => 0600,
        -create  => 'yes',
        -destroy => 'yes'
    ) or die $!;

    $shares[ $filter_number ]->store( freeze( $stats ) );

    my $pid = fork();
    if ( $pid != 0 ){
        warn "m forks $forks"if $DEBUG;
        &master( $pid, $forks );
    }
    else{
        warn "w forks $forks" if $DEBUG;
        $0 = "$0 -d $dev -i $interval -f '$pcap_filters[$filter_number - 1]' (filter_number: $filter_number)";
        &child ( $filter_number );
        last;
    }
}

1;
