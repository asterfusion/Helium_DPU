# FusionNOS compile on EC2004Y
- git clone vpp1908 <ssh://git@git.asterfusion.com:7999/fus/vpp1908.git>
- cd vpp1908
- make install-dep
- make install-ext-deps
  - if need reinstall-ext-deps, exec command
  ```
  ubuntu: apt-get remove vpp-ext-deps
  ``` 
- make build-release
  - find some input **Marvell MUSDK not found - marvell_plugin disabled**
- make pkg-deb
- dpkg -i build-root/*.deb
  - Package python3-cffi is not installed. exec below command
    ```
    apt-get install python-cffi
    apt-get -f install 
    ```
- ```systemctl status vpp``` to check status  
