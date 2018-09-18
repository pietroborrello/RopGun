# RopGun

RopGun implements a transparent ROP mitigation technique based on runtime detection of abnormal control transfers using hardware performance counters found on commodity processors.

It exploits the fact that ROP payloads expose an abnormal behavior with respect to hardware predictors. In fact at runtime the return instructions of ROP code is deeply different from legitimate return instructions of the actual program, which are always paired with call instructions. 

Branch prediction on returns is usually really precise. It is implemented through the use of a Return Address Stack ({\tt RAS}) with {\tt N} entries, usually with {\tt N = 16}, populated at each call, and read at each return to predict the address to return to. Emulating the stack, the  {\tt RAS} is usually precise in predicting the next address, limited only by its size, and by the operating system context switches that can corrupt it. Hardware predictors fail to predict effectively return instructions in ROP payloads, since the {\tt Return Address Stack} was not populated with the address as no call preceded the return instruction. Therefore when the mis-predicted return instructions becomes significantly high, there is an high probability of a ROP payload being run.
