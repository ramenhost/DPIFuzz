A Fuzzing Framework for the QUIC Protocol
=====================

.. image:: https://godoc.org/github.com/QUIC-Tracker/quic-tracker?status.svg
    :target: https://godoc.org/github.com/QUIC-Tracker/quic-tracker
    :alt: Documentation status


The Fuzzing framework is designed as an extension of QUIC-Tracker(a test suite which comprises a minimal Go implementation of QUIC which is currently draft-22 and TLS-1.3 compatible.)

Installation
------------

You should have Go 1.9, tcpdump, libpcap libraries and headers as well as 
openssl headers installed before starting.

Run this command as well

``sudo apt-get install faketime libscope-guard-perl libtest-tcp-perl``


::

    go get -u github.com/QUIC-Tracker/quic-tracker  # This will fail because of the missing dependencies that should be build using the 4 lines below
    cd $GOPATH/src/github.com/mpiraux/pigotls
    make
    cd $GOPATH/src/github.com/mpiraux/ls-qpack-go
    make

The fuzzer and the test-suite is run using the scripts in ``bin/test_suite/``. For help
about their usage see:

::

    go run bin/test_suite/differential_fuzzer.go -h
    go run bin/test_suite/scenario_runner.go -h
    go run bin/test_suite/test_suite.go -h


Brief Explanation about the fuzzer architecture
------------------------------------------------
The fuzzer code is executed using the differential_fuzzer.go script in ``bin/test_suite/``. 

When run without specifying any value for the scenario flag, it will execute all the scenarios against all the hosts specifies in a .txt file which can be created in a format similar to the ietf_quic_hosts.txt file. In case more than one host is specified, the results of the execution will be the following two txt files


1. comparison_results.txt :- This specifies all the executions of the scenarios, where a difference in behaviour was detected between the hosts being tested.
2. seed_map.txt :- This contains a list of source values used for a random number generator for each execution of the senario. This can be used to regeberate the sequence of packets that detected the differences in implementations.

If vendors of implementations just wish to test their implementations and detect errors using the fuzzer, they can specify their server details in the hosts file and the fuzzer will execute without creating any comparison files.

The fuzzing logic lies in the EncodeandEncrypt function in the connection.go file. Two functions perform the fuzzing operation -

1. fuzz_frame
2. fuzz_payload

Both of these are located in the connection.go file and the code is self explanatory.

Docker
------

Docker builds exist on `Docker Hub`_.

::

    docker run --network="host" quictracker/quictracker /http_get -h
    docker run --network="host" quictracker/quictracker /scenario_runner -h
    docker run --network="host" quictracker/quictracker /test_suite -h

.. _Docker Hub: https://hub.docker.com/r/quictracker/quictracker/
