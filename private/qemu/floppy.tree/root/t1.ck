// test1.ck
s :: InfiniteSource(LENGTH 64, BURST 1, NOTS true)
//      -> q :: Queue
//      -> c :: Counter
        -> d :: Discard(BURST 1);

DriverManager(
        wait 1s, write s.active false,
        //print "done $(d.count) packets $(q.drops) drops in 1s"
        print "done $(d.count) packets drops in 1s"
);
