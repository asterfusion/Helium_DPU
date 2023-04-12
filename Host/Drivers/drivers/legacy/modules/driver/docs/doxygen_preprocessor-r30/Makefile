#
#
# CNNIC SDK
#
# Copyright (c) 2018 Cavium Networks. All rights reserved.
#
# This file, which is part of the CNNIC SDK which also includes the
# CNNIC SDK Package from Cavium Networks, contains proprietary and
# confidential information of Cavium Networks and in some cases its
# suppliers. 
#
# Any licensed reproduction, distribution, modification, or other use of
# this file or the confidential information or patented inventions
# embodied in this file is subject to your license agreement with Cavium
# Networks. Unless you and Cavium Networks have agreed otherwise in
# writing, the applicable license terms "OCTEON SDK License Type 5" can be
# found under the directory: $CNNIC_ROOT/licenses/
#
# All other use and disclosure is prohibited.
#
# Contact Cavium Networks at info@caviumnetworks.com for more information.
#
################################################################################
revision=`bzr version-info --custom --template '{revno}'`

all: dist


dist: DoxygenPreprocessor/doxygen_preprocessor.exe
	
	bzr export doxygen_preprocessor-r${revision}.tar.gz
	zip -r doxygen_preprocessor-r${revision}.zip DoxygenPreprocessor
	mkdir -p dist
	rm -rf dist/*
	mv doxygen_preprocessor-r${revision}* dist

DoxygenPreprocessor/doxygen_preprocessor.exe: *.py
	wpython setup.py py2exe
