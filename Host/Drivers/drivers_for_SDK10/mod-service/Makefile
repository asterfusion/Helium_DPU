


bin:
	
	cp ../Helium-ep-driver/drivers/mgmt_net/mgmt_net.ko  ./helium-mod-service
	
	
	cp ../Helium-ep-driver/drivers/legacy/modules/driver/src/host/linux/kernel/drv/octeon_drv.ko  ./helium-mod-service
	
	sudo tar -zcvf helium-mod-service.tar.gz  helium-mod-service
	sudo chmod +x makebin.sh
	cat makebin.sh  helium-mod-service.tar.gz >helium-mod.bin
	sudo chmod +x helium-mod.bin 
	rm -rf helium-mod-service.tar.gz

bin-alone:
	sudo tar -zcvf helium-mod-service.tar.gz  helium-mod-service
	sudo chmod +x makebin.sh
	cat makebin.sh  helium-mod-service.tar.gz >helium-mod.bin
	sudo chmod +x helium-mod.bin 
	rm -rf helium-mod-service.tar.gz