# RopGun

RopGun is a Linux implementation of a transparent ROP mitigation technique based on runtime detection of abnormal control transfers using hardware performance counters found on commodity processors.

It exploits the fact that ROP payloads expose an abnormal behavior with respect to hardware predictors. In fact at runtime the return instructions of ROP code is deeply different from legitimate return instructions of the actual program, which are always paired with call instructions.

Branch prediction on returns is usually really precise. It is implemented through the use of a Return Address Stack (RAS) with N entries, usually with N = 16, populated at each call, and read at each return to predict the address to return to. Emulating the stack, the  RAS is usually precise in predicting the next address, limited only by its size, and by the operating system context switches that can corrupt it. Hardware predictors fail to predict effectively return instructions in ROP payloads, since the Return Address Stack was not populated with the address as no call preceded the return instruction. Therefore when the mis-predicted return instructions becomes significantly high, there is an high probability of a ROP payload being run.

RopGun wraps the executable to be protected and ptraces it to analyze the ret mis-prediciton ratio at every syscall issued. This significantly slows down the execution of a process (2x times on average), but protects it from ROP attacks.

Future work may involve developing kernel modules to gain efficiency in the monitor.

Inspired by the work of:
* kBouncer: Efficient and Transparent ROP Mitigation, Vasilis Pappas, Columbia University, 2012
* HDROP: Detecting ROP Attacks Using Performance Monitoring Counters, HongWei Zhou, ISPEC, 2014

## Installation

The tool works thanks to the access to hardware performance counters, it inspects events related to return that are retired, and return that are mis-predicted. Since such events are CPU specific the tool must be set up changing default values in the main source before using it.

This are the default values for intel 2^nd generation CPUs. You should see the Chapter 19 of the Intel manual [here]( https://software.intel.com/sites/default/files/managed/a4/60/325384-sdm-vol-3abcd.pdf) to set yours.

```c
#define RETIRED_BRANCES 0x88 // <- RAW EVENT NUM
#define MISPREDICTED_BRANCES 0x89 // <- RAW EVENT NUM
#define RET_MASK 0x88 // <- UMASK VALUE
```

For example the right values for 6th generation, 7th generation and 8th generation INTEL CORE processors are:
```c
#define RETIRED_BRANCES 0xC4 // <- RAW EVENT NUM
#define MISPREDICTED_BRANCES 0xC5 // <- RAW EVENT NUM
#define RET_MASK 0x08 // <- UMASK VALUE
```

Finally:
```shell
$ make
$ sudo make install
```

## Usage

```shell
$ ropgun -m [process]
```
To simply monitor performance counter efficacy on a particular binary

```shell
$ ropgun -k [process]
```
To kill the process if mis-prediction ratio suggests ROP payloads executing

Pleace notice that the process being run should be an ELF executable file, and you should provide the full or relative path to it.
