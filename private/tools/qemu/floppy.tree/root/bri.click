//
// $Id$
//
// A sample test configuration for click
//
//
// create a switch

sw :: EtherSwitch;

// two input devices

c0 :: FromDevice(ix0, BURST 30, PROMISC true);
c1 :: FromDevice(ix1, BURST 30, PROMISC true);

// and now pass packets around

c0[0] -> [0]sw[0] -> Queue(10000) -> ToDevice(ix0);
c1[0] -> [1]sw[1] -> Queue(10000) -> ToDevice(ix1);
