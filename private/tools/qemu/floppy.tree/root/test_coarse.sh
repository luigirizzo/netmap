#info
INFO=131.114.58.84
OL5=131.114.59.241

#
# test per vedere l'andamento degli ack su download da info
# la wmem non influisce, ma ne tengo nota
#echo "4096  16384   65536" > /proc/sys/net/ipv4/tcp_wmem 
#./ipfw/ipfw pipe 1 config coarse rates queue 800KBytes
#./ipfw/ipfw add 1 pipe 1 all from $INFO to $OL5 src-port 80
#./ipfw/ipfw add 2 pipe 1 all from $OL5 to $INFO dst-port 80

#
# test per vedere l'andamento degli ack su download da info
# la wmem non influisce, ma ne tengo nota
# PRIORITA' AGLI ACK
#echo "4096  16384   65536" > /proc/sys/net/ipv4/tcp_wmem 
#./ipfw/ipfw pipe 1 config coarse rates queue 800KBytes
#./ipfw/ipfw queue 1 config pipe 1 weight 1
#./ipfw/ipfw queue 2 config pipe 1 weight 10
#./ipfw/ipfw add 1 queue 1 all from $INFO to $OL5 src-port 80
#./ipfw/ipfw add 2 queue 2 all from $OL5 to $INFO dst-port 80

#ifconfig lo mtu 1500
#./ipfw/ipfw pipe 1 config coarse rates
#./ipfw/ipfw add 1 pipe 1 all from 131.114.59.241 to 131.114.59.241 dst-port 80 in
#./ipfw/ipfw add 2 pipe 1 all from 131.114.59.241 to 131.114.59.241 src-port 80 out

# the default mtu for loopback is 16k, use 1500 instead
ifconfig lo mtu 1500
# configure the pipe and the rules
./ipfw/ipfw pipe 1 config coarse rates
./ipfw/ipfw add 1 pipe 1 all from any to 127.0.0.1 dst-port 80 in
./ipfw/ipfw add 2 pipe 1 all from any to 127.0.0.1 src-port 80 out

