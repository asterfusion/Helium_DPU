#!/usr/bin/python
# -*- coding: utf-8 -*-

#####################################################################
# Doxygen Preprocessor - Doxygen Comment Locator                    #
# Author  : A. S. Budden                                            #
#####################################################################

# Core modules:
import os
import sys
import re


def FindDoxygenComments(lineArray, options):
	'''Find the location of all Doxygen Comment Blocks in a file.
	'''
	CommentBlocks = []
	LineIndex = -1
	CommentStart = None
	FoundCommentStart = False
	for line in lineArray:
		LineIndex += 1

		if not FoundCommentStart:
			for delimiter in ('/**', '/*!'):
				CommentStart = line.find(delimiter)
				if CommentStart != -1:
					CommentStart = \
							{ \
							'LineIndex': LineIndex, \
							'LinePosition': CommentStart + len(delimiter) \
							}
					FoundCommentStart = True
					break

		if not FoundCommentStart:
			for delimiter in ('///', '//!'):
				CommentStart = line.find(delimiter)
				if CommentStart != -1:
					CommentStart = \
							{ \
								'LineIndex': LineIndex, \
								'LinePosition': CommentStart + len(delimiter) \
							}
					CommentEnd = \
							{ \
								'LineIndex': LineIndex, \
								'LinePosition': len(line)+1 \
							}
					DoxygenCommentBlock = \
							{ \
								'Start': CommentStart, \
								'End': CommentEnd \
							}
					CommentBlocks.append(DoxygenCommentBlock)
					break


		if FoundCommentStart:
			CommentEnd = line.find('*/')
			if CommentEnd != -1:
				CommentEnd = \
						{ \
							'LineIndex': LineIndex, \
							'LinePosition': CommentEnd \
						}
				DoxygenCommentBlock = \
						{ \
							'Start': CommentStart, \
							'End': CommentEnd \
						}
				CommentBlocks.append(DoxygenCommentBlock)
				FoundCommentStart = False

	return CommentBlocks

def ExtractCommentBlocks(lineArray, options, CommentBlocks=None):
	'''Extract the content of all Doxygen Comment Blocks in a file.
	'''
	
	if CommentBlocks is None:
		CommentBlocks = FindDoxygenComments(lineArray, options)

	BlockArray = []
	for block in CommentBlocks:
		FullBlock = {}
		FullBlock['Location'] = block

		Start = block['Start']
		End = block['End']

		if Start['LineIndex'] == End['LineIndex']:
			BlockContents = [lineArray[Start['LineIndex']][Start['LinePosition']:End['LinePosition']].strip()]
		else:
			BlockContents  = [lineArray[Start['LineIndex']][Start['LinePosition']:].strip()]
			for Index in range(Start['LineIndex']+1, End['LineIndex']):
				BlockContents += [lineArray[Index].strip()]
			BlockContents += [lineArray[End['LineIndex']][:End['LinePosition']].strip()]

		for Index in range(len(BlockContents)):
			if BlockContents[Index].startswith('*'):
				BlockContents[Index] = BlockContents[Index][1:].strip()

		FullBlock['Contents'] = BlockContents

		BlockArray.append(FullBlock)

	return BlockArray

def IsCommentBlockStart(LineNumber, CommentBlocks):
	for block in CommentBlocks:
		if block['Location']['Start']['LineIndex'] == LineNumber:
			return True
	return False

def IsCommentBlockEnd(LineNumber, CommentBlocks):
	for block in CommentBlocks:
		if block['Location']['End']['LineIndex'] == LineNumber:
			return True
	return False

def IsInCommentBlock(LineNumber, CommentBlocks):
	for block in CommentBlocks:
		if block['Location']['End']['LineIndex'] > LineNumber and \
				block['Location']['Start']['LineIndex'] < LineNumber:
			return True
	return False

def GetCommentBlock(LineNumber, CommentBlocks):
	for block in CommentBlocks:
		if block['Location']['End']['LineIndex'] >= LineNumber and \
				block['Location']['Start']['LineIndex'] <= LineNumber:
			return block

	return None

def SplitLine(Line, LineNumber, CommentBlocks):
	if IsCommentBlockStart(LineNumber, CommentBlocks) and IsCommentBlockEnd(LineNumber, CommentBlocks):
		block = GetCommentBlock(LineNumber, CommentBlocks)
		return (
				Line[0:block['Location']['Start']['LinePosition']] +
				" " +
				Line[block['Location']['End']['LinePosition']:],
				Line[block['Location']['Start']['LinePosition']:block['Location']['End']['LinePosition']-1]
				)

	elif IsCommentBlockStart(LineNumber, CommentBlocks):
		block = GetCommentBlock(LineNumber, CommentBlocks)
		return (Line[0:block['Location']['Start']['LinePosition']],
			Line[block['Location']['Start']['LinePosition']+3:])

	elif IsCommentBlockEnd(LineNumber, CommentBlocks):
		block = GetCommentBlock(LineNumber, CommentBlocks)
		return (Line[block['Location']['End']['LinePosition']:],
			Line[0:block['Location']['End']['LinePosition']-1])

	elif IsInCommentBlock(LineNumber, CommentBlocks):
		return (None, Line)
	else:
		return (Line, None)

# Implementation:
def BlockHandler(lineArray, options, StartDelimiter, EndDelimiter, Processor):
	ProcessedLines = []

	# Get the full comment blocks
	CommentBlocks = ExtractCommentBlocks(lineArray, options)

	# Find statemachine lines
	Blocks = []
	FoundBlockStart = False
	for BlockIndex in range(len(CommentBlocks)):
		block = CommentBlocks[BlockIndex]
		LineOffset = 0
		for line in block['Contents']:
			if line.find(StartDelimiter) != -1:
				FoundBlockStart = True
				BlockStart = block['Location']['Start']['LineIndex'] + LineOffset

			if FoundBlockStart and line.find(EndDelimiter) != -1:
				FoundBlockStart = False
				BlockEnd = block['Location']['Start']['LineIndex'] + LineOffset
				Blocks.append({'Start': BlockStart, 'End': BlockEnd})

			LineOffset += 1

	# We now have the locations of all doxygen comments in CommentBlocks
	# and of all relevant blocks in Blocks
	LatestLine = 0
	for block in Blocks:
		for line in lineArray[LatestLine:block['Start']]:
			ProcessedLines.append(line)
		ProcessedLines += Processor(lineArray, block, CommentBlocks)
		LatestLine = block['End'] + 1

	for line in lineArray[LatestLine:]:
		ProcessedLines.append(line)
			
	return ProcessedLines

if __name__ == "__main__":
	# Parse command line
	from doxygen_preprocessor import CommandLineHandler
	options, remainder = CommandLineHandler()

	if len(remainder) > 0:
		fh = open(remainder[0])
		lineArray = [line.rstrip() for line in fh]
		fh.close()
	else:
		lineArray = [line.rstrip() for line in sys.stdin]

	FullBlocks = ExtractCommentBlocks(lineArray, options)

	for block in FullBlocks:
		sys.stdout.write("<BLOCK>")
		for line in block['Contents']:
			sys.stdout.write(line + "\n")
		sys.stdout.write("</BLOCK>\n")


# vim:encoding=utf-8

