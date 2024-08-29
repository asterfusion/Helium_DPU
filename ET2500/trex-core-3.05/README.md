# How to run in ET2500
## Compile
```shell
cd linux_dpdk/
./b configure --no-bnxt  --no-mlx=all
./b build
cd ..
```
## Run
- start trex in first connect session
```shell
cd script
./t-rex-64 -i --no-flow-control-change -c 2 --checksum-offload-disable --cfg cfg/cnxk_cfg.yaml
```
- start trex-console in another connect session
```shell
cd script
./trex-console
```

## Ref
- [trex doc](https://trex-tgn.cisco.com/trex/doc/index.html)
