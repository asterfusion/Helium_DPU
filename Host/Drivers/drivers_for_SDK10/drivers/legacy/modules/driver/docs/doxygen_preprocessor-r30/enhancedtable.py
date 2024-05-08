#!/usr/bin/python
# -*- coding: utf-8 -*-

#####################################################################
# Doxygen Preprocessor - State Machine Handler                      #
# Author  : A. S. Budden                                            #
#####################################################################

# Core modules:
import os
import sys
import re
import optparse
import logging

# Local modules
from error_handler import ReportError
from doxycomment import ExtractCommentBlocks,\
		IsCommentBlockStart, IsCommentBlockEnd,\
		IsInCommentBlock, GetCommentBlock,\
		SplitLine, BlockHandler

def ProcessTable(lineArray, TablePositions, CommentBlocks):
	# lineArray is the full array of file lines

	# TablePositions is a dictionary with 'Start' and 'End' being
	# the line indices into lineArray for the start and end of the comment
	# blocks containing @table and @endtable

	# CommentBlocks is details of where the comment blocks are
	TableHRRE = re.compile(r'^-+$')
	TableEntryRE = re.compile(r'^(\|.*\|)$')
	CrossRefRE = re.compile('^@ref\s+(?P<crossreference>\S+)\s+(?P<remainder>.*)')

	FoundTable = False
	TableLines = []
	TableParts = []
	DelayedLines = []
	TableRow = ""

	for LineNumber in range(TablePositions['Start'], TablePositions['End']+1):
		ThisLine = lineArray[LineNumber]

		index = ThisLine.find('@table')
		if index != -1:
			TableParts = [ThisLine[:index] + '<table id="DoxyEmbeddedTable">']
			TableRow = ""
			FoundTable = True
			continue

		if not FoundTable:
			TableLines.append(ThisLine)
			continue

		(Code, Comment) = SplitLine(ThisLine, LineNumber, CommentBlocks)

		if Comment is not None:
			Comment = Comment.strip()
			while Comment.startswith('*'):
				Comment = Comment[1:].strip()

			index = Comment.find('@endtable')
			if index != -1:
				FoundTable = False

				if len(TableRow) > 0:
					TableParts.append('<tr id="LastRow">' + TableRow + "</tr>")
				TableParts.append("</table>" + Comment[index+len('@endtable'):])

				TableLines.append(" ".join(TableParts))
				TableParts = []

				if Code is None:
					DelayedLines.append("")
				else:
					DelayedLines.append(Code)

				TableLines += DelayedLines
				DelayedLines = []
				continue

			# If there's no code, just add a blank line
			if Code is None:
				DelayedLines.append("")

			if TableHRRE.match(Comment) is not None:
				if len(TableRow) >0:
					TableParts.append('<tr id="HeadRow">' + TableRow + "</tr>")
					TableRow = ""
			elif TableEntryRE.match(Comment):
				m = TableEntryRE.match(Comment)
				TableRowString = m.group(1)
				if len(TableRow) > 0:
					TableParts.append('<tr id="BodyRow">' + TableRow + "</tr>")
				ColumnNumber = 0
				TableRow = ""
				if TableRowString.startswith('|'):
					TableRowString = TableRowString[1:]
				if TableRowString.endswith('|'):
					TableRowString = TableRowString[:-1]

				RowParts = TableRowString.split('|')

				for RowPart in RowParts:
					RowPart = RowPart.strip()
					Alignment = ""
					if RowPart.startswith('<'):
						RowPart = RowPart[1:].lstrip()
						Alignment = ' class="LeftAligned"'
					elif RowPart.startswith('>'):
						RowPart = RowPart[1:].lstrip()
						Alignment = ' class="RightAligned"'

					m = CrossRefRE.match(RowPart)
					if m is not None:
						CrossReference = r' href="\ref ' + m.group('crossreference') + '"'
						RowPart = m.group('remainder')
					else:
						CrossReference = ""

					ColumnNumber += 1

					if ColumnNumber == 1:
						ID = "FirstColumn"
					elif ColumnNumber == len(RowParts):
						ID = "LastColumn"
					else:
						ID = "MiddleColumn"

					TableRow += "<td" + Alignment \
							+ CrossReference \
							+ ' id="' + ID + '">' + RowPart + "</td>"

		if Code is not None:
			DelayedLines.append(Code)

	return TableLines


def EnhancedTableHandler(lineArray, options):

	return BlockHandler(lineArray, options,
			StartDelimiter='@table',
			EndDelimiter='@endtable',
			Processor=ProcessTable)

if __name__ == "__main__":
	# Parse command line
	from doxygen_preprocessor import CommandLineHandler
	options, remainder = CommandLineHandler()

	from filterprocessor import FilterFiles
	FilterFiles([EnhancedTableHandler,], options, remainder)

# vim:encoding=utf-8

