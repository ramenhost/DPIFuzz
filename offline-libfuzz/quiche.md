## QUICHE

```
cargo +nightly fuzz coverage packet_recv_server

ram@dpifuzz:~/Desktop/quiche$ llvm-cov-17 report target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/packet_recv_server -instr-profile=fuzz/coverage/packet_recv_server/coverage.profdata --ignore-filename-regex=.cargo* --ignore-filename-regex=h3 --ignore-filename-regex=octets --ignore-filename-regex=recovery

Filename                           Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

fuzz/src/packet_recv_server.rs           2                 0   100.00%           2                 0   100.00%           2                 0   100.00%           0                 0         -

quiche/src/cid.rs                      218               198     9.17%          61                49    19.67%         446               345    22.65%           0                 0         -

quiche/src/crypto.rs                   203               103    49.26%          44                17    61.36%         385               130    66.23%           0                 0         -

quiche/src/dgram.rs                     45                42     6.67%          19                17    10.53%          69                59    14.49%           0                 0         -

quiche/src/flowcontrol.rs               21                17    19.05%          11                 7    36.36%          49                31    36.73%           0                 0         -

quiche/src/frame.rs                    489               300    38.65%          20                14    30.00%         597               444    25.63%           0                 0         -

quiche/src/lib.rs                     2509              2004    20.13%         236               181    23.31%        4413              3310    24.99%           0                 0         -

quiche/src/minmax.rs                    39                38     2.56%           6                 5    16.67%          83                75     9.64%           0                 0         -

quiche/src/packet.rs                   414               254    38.65%          59                32    45.76%         537               275    48.79%           0                 0         -

quiche/src/path.rs                     215               185    13.95%          70                52    25.71%         441               338    23.36%           0                 0         -

quiche/src/rand.rs                       7                 7     0.00%           4                 4     0.00%          29                29     0.00%           0                 0         -

quiche/src/ranges.rs                    90                44    51.11%          27                13    51.85%         162                75    53.70%           0                 0         -

quiche/src/stream.rs                   434               314    27.65%         117                89    23.93%         897               636    29.10%           0                 0         -

quiche/src/tls.rs                      364               200    45.05%          71                30    57.75%         703               353    49.79%           0                 0         -

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

TOTAL 
```