#
# Copyright (c) 2020 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html
#

import os
import re
import sys
import string
import argparse
import subprocess

if sys.version_info >= (3, 0):
    from configparser import SafeConfigParser
else:
    from ConfigParser import SafeConfigParser

MAJOR_NUM = 1
MINOR_NUM = 0
REVISION = 0
devid_lbk_vf = "a0f8"
devid_evt_vf = "a0f9"
devid_inl_pf = "a0f0"

CPU_PART_CN96xx = "0x0b2"
CPU_PART_CN98xx = "0x0b1"
CPU_PART_CN10xx = "0xd49"

NUM_EVTDEV = 2
NUM_CPTDEV = 2
NUM_LBKDEV = 4
NUM_INLDEV = 1

EVENT_DEV_LIMIT = 50

SYS_DRV_PATH = "/sys/bus/pci/drivers"
SYS_DEV_PATH = "/sys/bus/pci/devices"


def findSystemArch():
    command = "cat /proc/cpuinfo"
    info = subprocess.check_output(command, shell=True).decode().strip()
    cpu_part = ""
    for line in info.split("\n"):
        if "CPU part" in line:
            cpu_part = re.sub(".*CPU part.*: ", "", line, 1)
            break
    if cpu_part == CPU_PART_CN96xx:
        return "_96xx"
    if cpu_part == CPU_PART_CN98xx:
        return "_98xx"
    if cpu_part == CPU_PART_CN10xx:
        return "_10xx"

    print("cpu part doesnt match 96/98/10xx")
    return "_unknown"


class CIRunner:
    def __init__(self, dir, verb, dry_run):
        # Modify the number of VFs and the kernel driver as needed.
        # =========================================================
        self.num_evtdev = NUM_EVTDEV
        self.num_cptdev = NUM_CPTDEV
        self.num_lbkdev = NUM_LBKDEV
        self.num_inldev = NUM_INLDEV
        self.drv_cptdev = b"rvu_cptpf"
        self.drv_lbkdev = b"rvu_nicpf"
        self.event_dev_id = devid_evt_vf.encode("UTF-8")
        # =========================================================
        self.evtpfbdf = None
        self.evtpfdev = None
        self.evtpfbdf2 = None
        self.evtpfdev2 = None
        self.cptpfbdf = None
        self.cptpfdev = None
        self.test_dir = dir
        self.drun = dry_run
        self.verb = verb
        out = subprocess.Popen(
            "uname -m".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = out.communicate()
        print("ARCH={}".format(stdout.decode("utf-8")))
        if b"x86" in stdout:
            exit("Cannot execute on x86")
        else:
            print("Starting CI Runner")

        self.arch_model = findSystemArch()

    def parse_through_event_devices(self, line):
        device = line.split(b" ")[0].decode("utf-8")

        # if arch is cn10k, then use pf device, as
        # kernel support is not available for vf
        if self.arch_model == "_10xx":
            return device, devid_evt_vf

        totalvfs_filePath = SYS_DEV_PATH + "/" + str(device) + "/sriov_totalvfs"

        if os.path.isfile(totalvfs_filePath):
            command = "cat " + totalvfs_filePath
            totalvfs = subprocess.check_output(command, shell=True).decode().strip()
            if int(totalvfs) > self.num_evtdev:
                return device, devid_evt_vf

        return None, None

    def init_pf(self):
        print("==== Init PF devices ====")

        cmd = subprocess.Popen(
            "dpdk-devbind.py -s",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for line in cmd.stdout:
            if self.drv_lbkdev in line:
                lnparse = line.split(b"'")
                dvparse = lnparse[1].split(b" ")
                self.lbkpfdev = dvparse[1].strip()
                self.lbkpfbdf = lnparse[0].strip()

            if self.drv_cptdev in line:
                lnparse = line.split(b"'")
                dvparse = lnparse[1].split(b" ")
                self.cptpfdev = dvparse[1].strip()
                self.cptpfbdf = lnparse[0].strip()

            if self.evtpfdev is None and self.event_dev_id in line:
                self.evtpfbdf, self.evtpfdev = self.parse_through_event_devices(line)

            elif (
                self.arch_model == "_10xx"
                and self.evtpfdev2 is None
                and self.event_dev_id in line
            ):
                self.evtpfbdf2, self.evtpfdev2 = self.parse_through_event_devices(line)

    def unbind_all(self):
        print("==== Unbind all VF devices bound to vfio-pci ====")

        cmd = subprocess.Popen(
            "dpdk-devbind.py -s | grep 'drv=vfio-pci'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        for line in cmd.stdout:
            lnparse = line.split(b" ")
            cmdstr = "echo {} > {}/{}/driver/unbind".format(
                lnparse[0].decode("utf-8"), SYS_DEV_PATH, lnparse[0].decode("utf-8")
            )
            self.run_cmd(cmdstr)

        cmdstr = "echo 0 > {}/{}/sriov_numvfs".format(SYS_DEV_PATH, self.evtpfbdf)
        self.run_cmd(cmdstr)

        cmdstr = "echo 0 > {}/{}/sriov_numvfs".format(
            SYS_DEV_PATH, self.cptpfbdf.decode("utf-8")
        )
        self.run_cmd(cmdstr)

    def set_limits_over_eventdev(self, limit, bdf):
        if self.arch_model == "_10xx":
            return
        self.set_limits(limit, bdf)

    def update_limits_over_eventdev(self):
        if self.arch_model == "_10xx":
            return

        # Clear limits on SSO and SSOW devices
        cmd = subprocess.Popen(
            "lspci -d:{}".format(self.evtpfdev.decode("utf-8")),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for line in cmd.stdout:
            lnparse = line.split(b" ")
            evtbdf = lnparse[0].strip()
            limit = 0
            self.set_limits(limit, evtbdf)

        # Set limits on Event devices
        limit = EVENT_DEV_LIMIT
        self.set_limits_over_eventdev(limit, self.evtpfbdf)

    def bind_driver(self, driver, dev_bdf):
        if self.arch_model == "_10xx":
            cmdstr = "dpdk-devbind.py -b " + driver + " " + dev_bdf
            self.run_cmd(cmdstr)

    def bind_evtdev_pf(self):
        if self.arch_model == "_10xx":
            if self.drun is False:
                os.system(
                    "echo 'event{}_bdf: {}' >> {}/{}".format(
                        1, self.evtpfbdf, self.test_dir, "configs/pcie.ini"
                    )
                )
                os.system(
                    "echo 'event{}_bdf: {}' >> {}/{}".format(
                        2, self.evtpfbdf2, self.test_dir, "configs/pcie.ini"
                    )
                )
            return

    def bind_evtdev_vf(self):
        self.bind_driver("vfio-pci", self.evtpfbdf)
        self.update_limits_over_eventdev()

        fnparse = self.evtpfbdf.split(".")
        fn = fnparse[1]
        dbdparse = fnparse[0]
        cmdstr = "echo {} > {}/{}/sriov_numvfs".format(
            self.num_evtdev, SYS_DEV_PATH, self.evtpfbdf
        )
        self.run_cmd(cmdstr)

        # Resolve Created VFs
        lspci = subprocess.Popen(
            "lspci | grep {}".format(dbdparse),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        evtcount = 1
        dbdparse = dbdparse.encode("utf-8")
        for line in lspci.stdout:
            if dbdparse in line:
                lnparse = line.split(b" ")
                if lnparse[0] != self.evtpfbdf.encode("utf-8"):
                    limit = 10
                    self.set_limits_over_eventdev(limit, lnparse[0])
                    cmdstr = "echo {} > {}/{}/driver/unbind".format(
                        lnparse[0].decode("utf-8"),
                        SYS_DEV_PATH,
                        lnparse[0].decode("utf-8"),
                    )
                    self.run_cmd(cmdstr)

                    cmdstr = "echo 177d a0fa > " + SYS_DRV_PATH + "/vfio-pci/new_id"
                    self.run_cmd(cmdstr)

                    if self.drun is False:
                        os.system(
                            "echo 'event{}_bdf: {}' >> {}/{}".format(
                                evtcount,
                                lnparse[0].decode("utf-8"),
                                self.test_dir,
                                "configs/pcie.ini",
                            )
                        )
                    evtcount = evtcount + 1

    def bind_evtdev(self):
        print("==== Binding Event devices ====")
        print("Using Eventdev PF device ID: {}".format(self.evtpfdev))
        print("Using Eventdev PF BDF: {}".format(self.evtpfbdf))
        self.evtpfbdf2 and print(
            "Using Eventdev PF device ID: {}".format(self.evtpfdev)
        )
        self.evtpfbdf2 and print("Using Eventdev PF BDF: {}".format(self.evtpfbdf2))

        if self.arch_model == "_10xx":
            self.bind_evtdev_pf()
        else:
            self.bind_evtdev_vf()

    def bind_cptdev(self):
        print("==== Binding CPT devices ====")
        print("Using CPT PF device ID: {}".format(self.cptpfdev.decode("utf-8")))
        print("Using CPT PF BDF: {}".format(self.cptpfbdf.decode("utf-8")))
        fnparse = self.cptpfbdf.split(b".")
        fn = fnparse[1]
        dbdparse = fnparse[0]
        cmdstr = "echo {} > {}/{}/sriov_numvfs".format(
            self.num_cptdev, SYS_DEV_PATH, self.cptpfbdf.decode("utf-8")
        )
        self.run_cmd(cmdstr)

        # Resolve Created VFs
        lspci = subprocess.Popen(
            "lspci | grep {}".format(dbdparse.decode("utf-8")),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        cptcount = 1
        for line in lspci.stdout:
            if dbdparse in line:
                lnparse = line.split(b" ")
                if lnparse[0] != self.cptpfbdf:
                    cmdstr = "echo {} > {}/{}/driver/unbind".format(
                        lnparse[0].decode("utf-8"),
                        SYS_DEV_PATH,
                        lnparse[0].decode("utf-8"),
                    )
                    self.run_cmd(cmdstr)

                    cmdstr = "echo 177d a0fe > " + SYS_DRV_PATH + "/vfio-pci/new_id"
                    self.run_cmd(cmdstr)

                    if self.drun is False:
                        os.system(
                            "echo 'crypto{}_bdf: {}' >> {}/{}".format(
                                cptcount,
                                lnparse[0].decode("utf-8"),
                                self.test_dir,
                                "configs/pcie.ini",
                            )
                        )
                    cptcount = cptcount + 1

    def bind_lbkdev(self):
        print("==== Binding LBK devices ====")

        # Resolve Pre-created VFs
        lspci = subprocess.Popen(
            "lspci -d:{}".format(devid_lbk_vf),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        lbkcount = 1
        for line in lspci.stdout:
            lnparse = line.split(b" ")
            if lbkcount <= self.num_lbkdev:
                cmdstr = "echo {} > {}/{}/driver/unbind".format(
                    lnparse[0].decode("utf-8"), SYS_DEV_PATH, lnparse[0].decode("utf-8")
                )
                self.run_cmd(cmdstr)

                cmdstr = "echo 177d a0f8 > " + SYS_DRV_PATH + "/vfio-pci/new_id"
                self.run_cmd(cmdstr)

                if self.drun is False:
                    os.system(
                        "echo 'lbk{}_bdf: {}' >> {}/{}".format(
                            lbkcount,
                            lnparse[0].decode("utf-8"),
                            self.test_dir,
                            "configs/pcie.ini",
                        )
                    )
            lbkcount = lbkcount + 1

    def bind_inldev(self):
        print("==== Binding Inline devices ====")

        # Resolve Inline device PFs
        lspci = subprocess.Popen(
            "lspci -d:{}".format(devid_inl_pf),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        inlcount = 1
        for line in lspci.stdout:
            lnparse = line.split(b" ")
            if inlcount <= self.num_inldev:
                cmdstr = "echo {} > {}/{}/driver/unbind".format(
                    lnparse[0].decode("utf-8"), SYS_DEV_PATH, lnparse[0].decode("utf-8")
                )
                self.run_cmd(cmdstr)

                cmdstr = "echo 177d a0f0 > " + SYS_DRV_PATH + "/vfio-pci/new_id"
                self.run_cmd(cmdstr)

                if self.drun is False:
                    os.system(
                        "echo 'inl{}_bdf: {}' >> {}/{}".format(
                            inlcount,
                            lnparse[0].decode("utf-8"),
                            self.test_dir,
                            "configs/pcie.ini",
                        )
                    )
            inlcount = inlcount + 1

    def set_limits(self, limit, evt_bdf):
        cmdstr = "echo {} > {}/{}/limits/sso".format(
            limit, SYS_DEV_PATH, evt_bdf.decode("utf-8")
        )
        self.run_cmd(cmdstr)
        cmdstr = "echo {} > {}/{}/limits/ssow".format(
            limit, SYS_DEV_PATH, evt_bdf.decode("utf-8")
        )
        self.run_cmd(cmdstr)

    def run_cmd(self, cmdstr):
        if self.drun:
            print(cmdstr)
        else:
            if self.verb:
                print(cmdstr)
            os.system(cmdstr)

    def enable_sriov(self):
        enable_sriov_file = "/sys/module/vfio_pci/parameters/enable_sriov"
        if os.path.isfile(enable_sriov_file):
            cmdstr = "echo 1 > " + enable_sriov_file
            self.run_cmd(cmdstr)
        else:
            print("File: " + enable_sriov_file + " doesnt exist")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-b",
        "--bind",
        action="store_true",
        default=False,
        help="Bind PCIe addresses to vfio-pci driver",
    )
    parser.add_argument(
        "-u",
        "--unbind",
        action="store_true",
        default=False,
        help="Unbind PCIe addresses from vfio-pci driver",
    )
    parser.add_argument(
        "-d",
        "--dryrun_bind",
        action="store_true",
        default=False,
        help="Dryrun bind PCIe addresses to vfio-pci driver",
    )
    parser.add_argument(
        "-g",
        "--dryrun_unbind",
        action="store_true",
        default=False,
        help="Dryrun unbind PCIe addresses from vfio-pci driver",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Optionally used with [-b|-u] for verbose output",
    )

    try:
        args = parser.parse_args()
    except:
        sys.exit("Call 'python ci_runner.py --help' for more info")

    print("Version = {}.{}.{}".format(MAJOR_NUM, MINOR_NUM, REVISION))
    if args.bind or args.unbind:
        dryrun = False
    elif args.dryrun_bind or args.dryrun_unbind:
        dryrun = True
    else:
        exit(parser.print_help())

    if args.verbose:
        verb = True
    else:
        verb = False

    # Read the environment variable 'TEST'. Exit if it is not set
    test_dir = os.environ.get("TEST_DIR")
    if test_dir is None:
        exit("Please set the environment 'TEST_DIR'")

    runner = CIRunner(dir=test_dir, verb=verb, dry_run=dryrun)

    os.system("> {}/configs/pcie.ini".format(test_dir))
    os.system("echo '[default]' >> {}/configs/pcie.ini".format(test_dir))

    # Init PF devices
    runner.init_pf()

    if args.unbind or args.dryrun_unbind:
        # Unbind all devices bound to vfio-pci
        runner.unbind_all()
    else:
        runner.enable_sriov()
        # Bind event-dev
        runner.bind_evtdev()
        # Bind cpt-dev
        runner.bind_cptdev()
        # Bind lbk-dev
        runner.bind_lbkdev()
        # Bind inline-dev
        runner.bind_inldev()
