#Tcpreplay clone
##Overview
This software is a cloned version of the original one, made for working with
netmap (see http://info.iet.unipi.it/~luigi/netmap/ for more information 
about netmap). 
This software works in two different modes:
* Replay
* Pcap

##Replay
In replay mode the user provides two different netmap interfaces.
The software accepts all the incoming packets from one interface and retransmits 
them on the other one. This retransmission works in both direction.

##Pcap
In this mode the user provides one interface and one capture file (.cap).
The software replays the content of the file to the specified interface. In
particular the software supports three different transmission timing: real, 
fixed bandwidth and maximum speed.

##Usage options
Replay mode accepts the following options:
* B	bandwidth in bps (only for replay mode)
* D	delay in seconds (only for replay mode)
* Q	qsize in bytes	(both modes)
* L	loss probability (only for replay mode)
* i	interface name (two mandatory, see below for more details)
* v	verbose	(only for replay mode)
* b	batch size	(only for replay mode)
* m mode	(only for pcap mode)

###Bandwidth
If the -B option is used, tcpreplay transmits packets with the given bandwidth.
Bandwidths are expressed in bits per second, can be followed by a
character specifying a different unit e.g.

<table>
<tr><td>b/B</td><td>bits per second</td></tr>
<tr><td>k/K</td><td>kbits/s (10^3 bits/s)</td></tr>
<tr><td>m/M</td><td>mbits/s (10^6 bits/s)</td></tr>
<tr><td>g/G</td><td>gbits/s (10^9 bits/s)</td></tr>
</table>

Currently implemented options

<table>
<tr><td>const,b</td><td>constant bw, excluding mac framing</td></tr>
<tr><td>ether,b</td><td>constant bw, including ethernet framing (20 bytes framing + 4 bytes crc)</td></tr>
</table>

###Delay			
Specifiyng the delay options -D let the program randomly choose a sequence of 
values to be used as delays introduced at each packet.
Times are in nanoseconds, can be followed by a character specifying
    a different unit e.g.

<table>
<tr><td>n</td><td>nanoseconds</td></tr>
<tr><td>u</td><td>microseconds</td></tr>
<tr><td>m</td><td>milliseconds</td></tr>
<tr><td>s</td><td>seconds</td></tr>
</table>

Currently implemented options:

<table>
<tr><td>constant,t</td><td>constant delay equal to t</td></tr>
<tr><td>uniform,tmin,tmax</td><td>uniform delay between tmin and tmax</td></tr>
<tr><td>exp,tavg,tmin</td><td>exponential distribution with average tavg and 
minimum tmin (corresponds to an exponential distribution with argument 1/(tavg-tmin) )</td></tr>
</table>

###Queue size
The -Q options set the queue size to the given value. If the user does not 
specify a queue size, 50k is used as default value.
Sizes are in bytes, but suffixes can be used for different units e.g.

<table>
<tr><td>k/K</td><td>kilobytes (1024 bytes)</td></tr>
<tr><td>m/M</td><td>megabytes (1024^2 bytes)</td></tr>
<tr><td>g/G</td><td>gigabytes (1024^3 bytes)</td></tr>
</table>

###Loss probability
The -L option sets a loss probability. Loss is expressed as packet or bit error 
rate, which is an absolute number between 0 and 1 (typically small).
Currently implemented options

<table>
<tr><td>plr,p</td><td>uniform packet loss rate p, independent of packet size</td></tr>
<tr><td>burst,p</td><td>burst loss with burst probability p and burst length uniformly distributed between lmin and lmax</td></tr>
<tr><td>ber,p</td><td>uniformly distributed bit error rate p, so actual loss prob. depends on size.</td></tr>
</table>

###Interface
The -i option specifies the interface to be used. Two interfaces are mandatory 
while operating in replay mode. On the other hand, in pcap mode, tcpreplay needs
just a single output interface and a .cap source file.

###Verbose
The -v option enables output of additiona informations during execution.

###Batch
The -b option sets the burst size, if not used the default value is 1024.
Valid range is between 1 and 8192.

###Transmission mode
The -m option specifies the pcap transmission mode.
Currently implemented options are

<table>
<tr><td>real</td><td>packets are sent using times taken from pcap</td></tr>
<tr><td>fast</td><td>packets are sent as fast as possible</td></tr>
<tr><td>fixed,b</td><td>packets are sent with a fixed bandwidth b</td></tr>
</table>

##Examples
In replay mode, reads incoming traffic from eth0 and retransmits it on eth1 
 ```
 sudo ./tcpreplay -i netmap:eth0 -i netmap:eth1
 ```
In replay mode, reads incoming traffic from eth0 and retransmits it on eth1 
with constant bandwidth 100k, connstant delay 1s and uniform loss probability 
0.5
 ```
 sudo ./tcpreplay -i netmap:eth0 -i netmap:eth1 -B const,100k -D const,1s -L 
 plr,0.5
 ```
In pcap mode, reads from a pcap file and retransmits on a port of the VALE 
switch with fast transmission mode
 ```
 sudo ./tcpreplay -i file.cap -i vale:1 -m fast
 ```
 In pcap mode, reads from a pcap file and retransmits on a pipe using the VALE 
switch with fixed transmission mode
 ```
 sudo ./tcpreplay -i file.cap -i vale1:a\{1 -m fixed,100k
 ```
 
##Author
This code is written by Luigi Rizzo, Andrea Beconcini, Francesco Mola and 
Lorenzo Biagini 
