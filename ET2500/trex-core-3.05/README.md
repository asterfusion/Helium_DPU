# How to run in ET2500
## Compile
### Ubuntu install deps
```shell
apt-get install -y \
    libpgm-5.3 \ 
    libnorm-dev \
    libzmq5 \

```

### Continue build
```shell
  cd linux_dpdk/
  ./b configure --no-bnxt  --no-mlx=all
  ./b build
  cd ..
```

## Run
- use dpdk-devbind.py to bind ports

- use python3.11 older version
  download python3.11 source code, build and install
```shell
  wget 'https://www.python.org/ftp/python/3.11.9/Python-3.11.9.tgz'
  tar -zxf Python-3.11.9.tgz
  cd Python-3.11.9
  ./configure
  make
  make install
```

- start trex in first connect session
```shell
cd script
./_t-rex-64 -i --no-flow-control-change -c 2 --checksum-offload-disable --cfg cfg/cnxk_cfg.yaml
```
- start trex-console in another connect session
```shell
cd script
./trex-console
```

## Ref
- [trex doc](https://trex-tgn.cisco.com/trex/doc/index.html)
