#!/usr/bin/python
# -*- coding: utf-8 -*-

#####################################################################
# Doxygen Preprocessor - Error Handler                              #
# Author  : A. S. Budden                                            #
#####################################################################

# Core modules:
import sys

def _functionId(nFramesUp):
	""" Create a string naming the function n frames up on the stack.
	"""
	co = sys._getframe(nFramesUp+1).f_code
	return "%s (%s @ %d)" % (co.co_name, co.co_filename, co.co_firstlineno)

def ReportError(Message):
	""" Call this function to report an error message and show the code location.
    """
	raise Exception("Error: %s (%s)" % (Message, _functionId(1)))

# vim:encoding=utf-8

