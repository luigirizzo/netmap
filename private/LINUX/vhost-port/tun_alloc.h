#include <linux/if_tun.h>
#include <net/if.h>

int tun_alloc( char *dev, int flags );

/* SHELL COMMANDS
	per creare ed eliminare interfacce TUN/TAP persistenti (iproute2)
		ip tuntap add mode tun name tun0
		ip tuntap add mode tun name tun1
	
	per assegnare indirizzi IP alle interfacce
		ip link set tun0 up
		ip link set tun1 up
		ip addr add 10.0.0.1/24 dev tun0
		ip addr add 10.0.0.2/24 dev tun1

	bridging (non serve in questo caso)
		brctl addbr br0
		brctl addif br0 tun0
		brctl addif br0 tun1
		ip addr del 10.0.0.1/24 dev tun0
		ip addr del 10.0.0.2/24 dev tun1
		ip link set br0 up
		ip addr add 10.0.0.1/24 dev br0
	...
*/
