A Structured Fuzzing Framework for the QUIC Protocol
=====================

The Fuzzing framework is designed using the QUIC API provided by QUIC-Tracker(a test suite which comprises a minimal Go implementation of QUIC). It is currently draft-27 and TLS-1.3 compatible.

Installation
------------

You should have Go 1.9, tcpdump, libpcap libraries and headers as well as 
openssl headers installed before starting.

Run these command as well

``sudo apt-get install faketime libscope-guard-perl libtest-tcp-perl``

``sudo apt-get install make``

``sudo apt-get install cmake``

``sudo apt-get install build-essential``

``sudo apt-get install pkg-config``

``sudo apt-get install libssl-dev``


::

    go get -u github.com/QUIC-Tracker/quic-tracker  # This will fail because of the missing dependencies that should be build using the 4 lines below
    cd $GOPATH/src/github.com/mpiraux/pigotls
    make
    cd $GOPATH/src/github.com/mpiraux/ls-qpack-go
    make
    
After this, run the following commands:

::

    cd $GOPATH/src/github.com/QUIC-Tracker
    rm -rf quic-tracker
    git clone https://github.com/piano-man/DPIFuzz.git
    mv ./DPIFuzz ./quic-tracker


The fuzzer is run using the scripts in ``bin/fuzzer/``. For help
about their usage see:

::

    go run bin/fuzzer/modular_differential_fuzzer.go -h
    go run bin/fuzzer/fuzzer_runner.go -h


Brief Explanation about the fuzzer architecture
------------------------------------------------
The fuzzer code is executed using the fuzzer_runner.go script in ``bin/fuzzer/`` and if you want to use the fuzzer for differential analysis, use the script modular_differential_fuzzer.go in ``bin/fuzzer/`` . Remember to use the fuzz flag and set it to 1. Both these scripts run the fuzzer.go script contained in ``fuzzer/`` which is the actual fuzzer code.

The fuzzer uses the generators in ``generators/`` to generate sequences of packets and the mutators are contained in ``mutators/``.
When the modular_differential_fuzzer.go script in ``bin/fuzzer/`` is run without specifying any value for the generator flag, it will execute the fuzzer using all the generators against all the hosts specified in a .txt file which can be created in a format similar to the ietf_quic_hosts.txt file. In case more than one host is specified, the results of the execution will be the following two .txt files


1. comparison_results.txt :- This specifies all the executions of the fuzzer, where a difference in behaviour was detected between the hosts being tested.
2. seed_map.txt :- This contains a list of source values used for a random number generator for each execution of the fuzzer. This can be used to regenerate the sequence of packets that detected the differences in implementations.

If vendors of implementations just wish to test their implementations and detect errors using the fuzzer, they can specify their server details in the hosts file and the fuzzer will execute without creating any comparison files.
