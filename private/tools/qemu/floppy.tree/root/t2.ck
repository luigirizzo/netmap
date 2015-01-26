// test1.ck
FromDevice(ix0, BURST 100) -> Discard;

s :: FromDevice(ix1, BURST 100) -> Queue -> ToDevice(ix0, BURST 100);

DriverManager(
	set a 0,
	label x,
	wait 1s,
	set b $(s.count),
	print "done $(sub $b $a) packets in 1s",
	set a $b,
	goto x 1
);
