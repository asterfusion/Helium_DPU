#!/usr/bin/python
# -*- coding: utf-8 -*-

#####################################################################
# Doxygen Preprocessor - Top Level Processor                        #
# Author  : A. S. Budden                                            #
#####################################################################

# Core modules:
import os
import sys
import re
import optparse
import logging


# Implementation:

def FilterFiles(ProcessOrder, options, remainder):

	# Run Implementation:
	if len(remainder) > 0:
		# If a file name is provided on the command line, open it
		fh = open(remainder[0])
		lineArray = [line.rstrip() for line in fh]
		fh.close()
	else:
		# Otherwise, read from stdin
		lineArray = [line.rstrip() for line in sys.stdin]

	for processor in ProcessOrder:
		lineArray = processor(lineArray, options)

	for line in lineArray:
		sys.stdout.write(line + "\n")

def main():
	# Parse command line
	from doxygen_preprocessor import CommandLineHandler
	options, remainder = CommandLineHandler()

	# Run Implementation:
	FilterFiles([], options, remainder)



if __name__ == "__main__":
	main()

# vim:encoding=utf-8

