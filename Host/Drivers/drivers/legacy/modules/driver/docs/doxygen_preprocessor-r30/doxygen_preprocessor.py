#!/usr/bin/python
# -*- coding: utf-8 -*-

#####################################################################
# Doxygen Preprocessor - Main                                       #
# Author  : A. S. Budden                                            #
#####################################################################

# Core modules:
import os
import sys
import re
import optparse
import logging


# Processes to run:
ProcessOrder = []

from enhancedtable import EnhancedTableHandler
ProcessOrder.append(EnhancedTableHandler)

from statemachine import StateMachineHandler
ProcessOrder.append(StateMachineHandler)

def CommandLineHandler():
	"""Option parser interface."""

	# Create optparse instance
	parser = optparse.OptionParser()

	# Add the parser options
	parser.add_option('--just-dot',
			action="store_true",
			dest="just_dot",
			default=False,
			help="Just print out the dot lines")
	parser.add_option('--debug',
			action="store_true",
			dest="debug",
			default=False,
			help="Debug Mode")

	# Bash Autocompletion code:
	try:
		import optcomplete
		optcomplete_on = True
	except:
		optcomplete_on = False
	if optcomplete_on:
		optcomplete.autocomplete(parser)

	# Parse the command line options
	options, remainder = parser.parse_args()

	return options, remainder
	
def main():
	global ProcessOrder

	# Parse command line
	options, remainder = CommandLineHandler()

	# Run Implementation:
	from filterprocessor import FilterFiles
	FilterFiles(ProcessOrder, options, remainder)



if __name__ == "__main__":
	main()

# vim:encoding=utf-8

