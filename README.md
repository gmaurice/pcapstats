pcapstats
=========

Monitor network packets on a specific device. The gathered statistics are printed regularly on stdout, in csv format.
 
 - Supports CSV output format
 - Supports several filters and several statistics
 - Statistics are printed every "interval" seconds

Examples:
 - Inline execution :

    __sudo./pcapstats.pl -d bond0:0 -i 60 
    -f "port 443 and not (dst host $MYIP and dst port 443)"
    -f "port 80 and not (dst host $MYIP and dst port 80)"
    -s "1.cum(len)" -s "2.cum(len)"__

    Capturing packets on bond0:0, print pcap stats every 60 secs.
    
    CSV output headers:
    
    filter_number(1),timestamp,rx.cum(len),tx.cum(len)
    
    filter_number(2),timestamp,rx.cum(len),tx.cum(len)
    
    1,1374861169,94499506,4930685
    
    2,1374861169,67693990,788298
    
    1,1374861229,223324153,10181579
    
    2,1374861229,77240227,1594904
    
    1,1374861289,324061045,15198566
    
    2,1374861289,87413943,2370888
