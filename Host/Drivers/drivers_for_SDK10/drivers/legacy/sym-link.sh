#!/bin/bash

if [ -z "$CNNIC_ROOT" ]; then
    echo -e "\n\tERROR: CNNIC environment not set\n"
    exit;
fi

CMD="ln -sf"
if [ "$1" = "undo" ]; then
	CMD="fileremove"
fi

fileremove()
{
	file=$2
	[ -z "$2" ] && { file=`basename $1`; }
	rm -f $file
}


cd $CNNIC_ROOT/modules/driver/bin;
$CMD ../src/host/linux/kernel/drv/Module.symvers

cd $CNNIC_ROOT/modules/driver/inc;
$CMD ../src/driver.mk

for file in cn83xx_pf_device.h octeon_debug.h octeon_device.h octeon_droq.h octeon_hw.h octeon_instr.h octeon_iq.h octeon_macros.h pending_list.h response_manager.h octeon_mailbox.h; do
	$CMD ../src/host/osi/$file
done

for file in cn83xx_vf_device.h;  do
   $CMD ../src/host/osi/octvf/$file
done

for file in cvm_linux_types.h linux_sysdep.h octeon_main.h; do
	$CMD ../src/host/linux/kernel/drv/$file
done

#for file in cavium-list.h cn83xx_pf_regs.h cn83xx_vf_regs.h octeon-common.h octeon_config.h octeon-drv-opcodes.h octeon-error.h octeon-opcodes.h octeon-pci.h oct_test_list.h oct_test_list.c octeon-nic-common.h cnnic_version.h; do
#	$CMD ../src/common/$file
#done

$CMD ../src/host/linux/user/api/octeon_user.h

rm -rf linux;mkdir linux; cd linux; $CMD ../../../driver/inc/linux_sysdep.h;cd ..
rm -rf osi;mkdir osi; cd osi; $CMD ../../../driver/inc/cavium_sysdep.h

cd $CNNIC_ROOT
