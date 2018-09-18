# RopGun

RopGun implements a transparent ROP mitigation technique based on runtime detection of abnormal control transfers using hardware performance counters found on commodity processors.

It exploits the fact that ROP payloads expose an abnormal behavior with respect to hardware predictors. In fact at runtime the return instructions of ROP code is deeply different from legitimate return instructions of the actual program, which are always paired with call instructions. 

Branch prediction on returns is usually really precise. It is implemented through the use of a Return Address Stack (RAS) with N entries, usually with N = 16, populated at each call, and read at each return to predict the address to return to. Emulating the stack, the  RAS is usually precise in predicting the next address, limited only by its size, and by the operating system context switches that can corrupt it. Hardware predictors fail to predict effectively return instructions in ROP payloads, since the Return Address Stack was not populated with the address as no call preceded the return instruction. Therefore when the mis-predicted return instructions becomes significantly high, there is an high probability of a ROP payload being run.

RopGun wraps the executable to be protected and ptraces it to analyze the ret misprediciton ratio at every syscall issued. This significantly slows down the execution of a process (2x times on average), but protects it from ROP attacks. 

Future work may involve developing kernel modules to gain efficience in the monitor.

Inspired by the work of:
* kBouncer: Efficient and Transparent ROP Mitigation, Vasilis Pappas, Columbia University, 2012
* HDROP: Detecting ROP Attacks Using Performance Monitoring Counters, HongWei Zhou, ISPEC, 2014 


