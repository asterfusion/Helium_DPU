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

iskeyword = '[A-Za-z0-9_]'
StateList = \
		[
				'PassThrough',
				'InDoxygenComment',
				'InStateMachine',
		]

StateAddRegExpString = r'^AddState\s+(?P<statename>' + iskeyword + r'+)\s+(?P<label>"[^"?]+?(?P<query>\?)?")$'
StateAddRE = re.compile(StateAddRegExpString)

def EscapeForRegExp(string):
	result = ""
	for character in string:
		if character in ['[', ']', '.', '*', '+', '?', '{', '}', '^', '$', '(', ')']:
			result += '\\'
		result += character
	return result

class Enumerate(object):
	def __init__(self, names):
		for number, name in enumerate(names):
			setattr(self, name, number)

def IsAcceptableCharacter(ch):
	AcceptableCharacters = []
	for CharacterRange in [['A','Z'],['a','z']]:
		AcceptableCharacters += [chr(i) for i in range(ord(CharacterRange[0]), ord(CharacterRange[1])+1)]
	AcceptableCharacters += ['_',]
	return ch in AcceptableCharacters

def SanitiseDotLink(dotlink):
	return filter(IsAcceptableCharacter, dotlink)

def DebugPrintCases(Cases):
	for case in Cases:
		print "{"
		for key in case.keys():
			if type(case[key]) == type(""):
				print "\t'" + key + "': '" + case[key] + "'"
			elif type(case[key]) == type([]):
				print "\t'" + key + "':"
				print "\t["
				for item in case[key]:
					print "\t\t" + item + ","
				print "\t]"
			else:
				print "\t'" + key + "': " + str(case[key])
		print "}"

def ProcessStateCases(Cases, GlobalStates, InitialLines, FunctionName=None):
	# Cases includes keys:
	#     State (string)
	#     FollowingStates (list of strings)
	#     CommentLines (list of strings)
	#     InitialCase (True/False)

	#DebugPrintCases(Cases)

	DotGraphLines = []
	DotGraphLines.append('@dot digraph {')

	LabelRE = re.compile(r'^Label\s+(?P<label>"[^"?]+?(?P<query>\?)?")$')
	LabelOmitRE = re.compile(r'^Label\s*OMIT$')
	EndStateRE = re.compile(r'^End\s+State$')
	DoxyRE = re.compile(r'^(?P<leader>.*)@doxy\s+(?P<doxystring>.*)$')
	LinkRE = re.compile(r'^(?:(?P<source>.*?)\s+)?(?P<linktype><?->?)\s+(?P<destination>.*?)(?:\s+\((?P<direction>[NESW]+)\))?$')
	QueryRE = re.compile(r'^".*\?"$')
	ComponentRE = re.compile(r'^(?P<state>.*?)(?:\.(?P<linktext>' + iskeyword + r'+))?(?P<direction>:[nesw]+)?$')
	LabelStartRE = re.compile('@label\s+(?P<remainder>.*)')
	LabelEndRE = re.compile('(?P<prelabel>.*?)\s*@endlabel')

	if FunctionName is not None:
		DotGraphLines.append(FunctionName + ' [label="' + FunctionName + '( )"];')
		DotGraphLines.append('{rank=source; ' + FunctionName + ';};')
	
	DotGraphLines += InitialLines

	for case in Cases:
		SkipCase = False
		Label = None
		RemoveLines = []
		FirstQueryState = None
		LinkSources = []

		# Find label
		InLabelBlock = False
		for commentline in case['CommentLines']:
			if InLabelBlock:
				m = LabelEndRE.match(commentline)
				RemoveLines.append(commentline)
				if m is not None:
					Label += m.group('prelabel')
					Label = '<' + Label + '>'
					InLabelBlock = False
					break
				else:
					Label += commentline
					continue

			m = LabelStartRE.match(commentline)
			if m is not None:
				Label = m.group('remainder')
				m = LabelEndRE.match(Label)
				RemoveLines.append(commentline)
				if m is not None:
					Label = '<' + m.group('prelabel') + '>'
					break
				else:
					InLabelBlock = True
					continue

			if LabelOmitRE.match(commentline):
				SkipCase = True
				break

			m = LabelRE.match(commentline)
			if m is not None:
				Label = m.group('label') # Includes quotes
				RemoveLines.append(commentline)
				break

		for line in RemoveLines:
			case['CommentLines'].remove(line)
			RemoveLines = []

		if SkipCase:
			continue

		if Label is None:
			ReportError("No label found for state %s" % case['State'])

		if case['InitialCase'] and FunctionName is not None:
			DotGraphLines.append(FunctionName + ' -> ' + case['State'] + ';')

		# Create State Marker:
		DotGraphLines.append(case['State'] + ' [label=' + Label + r' URL="\ref ' + case['State'] + '"];')

		if case['InitialCase'] and FunctionName is None:
			DotGraphLines.append('{rank=source; ' + case['State'] + ';};')

		# Handle end states
		EndState = False
		for commentline in case['CommentLines']:
			if EndStateRE.match(commentline):
				DotGraphLines.append('{rank=sink; ' + case['State'] + ';};')
				EndState = True
				break
		if EndState:
			continue

		# Add any additional states
		for commentline in case['CommentLines']:
			m = StateAddRE.match(commentline)
			if m is not None:
				RemoveLines.append(commentline)
				case['FollowingStates'].append(m.group('statename'))
				DotGraphLines.append(m.group('statename') + ' [label=' + m.group('label') + '];')

		for line in RemoveLines:
			case['CommentLines'].remove(line)
			RemoveLines = []

		case['QueryStates'] = {}

		# Handle line requests
		for commentline in case['CommentLines']:
			m = LinkRE.match(commentline)
			if m is not None:
				RemoveLines.append(commentline)
				if m.group('source') is None:
					SourceFull = case['State']
				else:
					SourceFull = m.group('source')
				LinkType = m.group('linktype')
				DestinationFull = m.group('destination')
				Direction = m.group('direction') # Maybe None

				m = ComponentRE.match(SourceFull)
				if m is not None:
					Source = m.group('state')
					if len(Source) == 0:
						if m.group('linktext') is None:
							ReportError('No source for link on state %s: %s' %  (case['State'], SourceFull))
						Source = case['State']
					SourceDirection = m.group('direction')
					LinkText = m.group('linktext')
				else:
					ReportError("Invalid source for link on state %s: %s" % (case['State'], SourceFull))

				if SourceDirection is None:
					if Direction is not None:
						SourceDirection = ":" + Direction.lower()
					else:
						SourceDirection = ""

				m = ComponentRE.match(DestinationFull)
				if m is not None:
					Destination = m.group('state')
					DestinationDirection = m.group('direction')
				else:
					ReportError("Invalid destination for link on state %s: %s" % (case['State'], DestinationFull))

				if DestinationDirection is None:
					if Direction is not None:
						DestinationDirection = ":" + Direction
					else:
						DestinationDirection = ""

				if LinkText is None:
					LinkText = ""
				else:
					LinkText = ' [label="' + LinkText + '"]'

				# If either are a query, convert to a state name
				for state in [Source, Destination]:
					m = QueryRE.match(state)
					if m is not None:
						if case['QueryStates'].has_key(state):
							# It's not a new state,
							NewStateName = case['QueryStates'][state]
						else:
							NewStateName = case['State'] + '_' + SanitiseDotLink(state)
							DotGraphLines.append(NewStateName + ' [label=' + state + ' shape="diamond"];')
							if FirstQueryState is None:
								FirstQueryState = NewStateName
							case['QueryStates'][state] = NewStateName

						if state == Source:
							Source = NewStateName
						else:
							Destination = NewStateName

				if Destination == "return":
					Destination = case['State']
				elif Destination == "continue":
					if len(case['FollowingStates']) == 1:
						Destination = case['FollowingStates'][0]
					else:
						ReportError("'continue' used with multiple following states in state '%s': %s" % (case['State'], case['FollowingStates']))
				else:
					if Destination not in (case['FollowingStates'] + case['QueryStates'].values() + case['OtherStates'] + GlobalStates):
						ReportError("Erroneous state link from state %s to state %s" % (case['State'], Destination))

				LinkSources.append(Source)
				# Now add the links
				DotGraphLines.append(Source + SourceDirection + \
						" " + LinkType + " " + \
						Destination + DestinationDirection + \
						LinkText + ';')

		for line in RemoveLines:
			case['CommentLines'].remove(line)
			RemoveLines = []

		for LinkSource in LinkSources:
			if LinkSource == case['State']:
				break
		else:
			# We haven't linked from this state
			if FirstQueryState is not None:
				DotGraphLines.append(case['State'] + " -> " + FirstQueryState + ';')
			elif len(case['FollowingStates']) == 1:
				DotGraphLines.append(case['State'] + " -> " + case['FollowingStates'][0] + ';')
			elif len(case['FollowingStates']) == 0 and len(case['OtherStates']) == 1:
				DotGraphLines.append(case['State'] + " -> " + case['OtherStates'][0] + ';')
			else:
				ReportError("No link from non-end state %s" % case['State'])

		# Add doxy lines
		for commentline in case['CommentLines']:
			m = DoxyRE.match(commentline)
			if m is not None:
				RemoveLines.append(commentline)
				DoxyString = m.group('doxystring')
				# TODO: Process Quoted States
				for key in case['QueryStates']:
					DoxyString = DoxyString.replace(key, case['QueryStates'][key])
				DotGraphLines.append(DoxyString)

		for line in RemoveLines:
			case['CommentLines'].remove(line)
			RemoveLines = []


		if len(case['CommentLines']) > 0:
			ReportError("Unhandled commands for state %s: %s" % (case['State'], str(case['CommentLines'])))

	DotGraphLines.append('} @enddot')
	return " ".join(DotGraphLines)

def ProcessStateMachine(lineArray, StateMachinePositions, CommentBlocks):
	# lineArray is the full array of file lines

	# StateMachinePositions is a dictionary with 'Start' and 'End' being
	# the line indices into lineArray for the start and end of the comment
	# blocks containing @statemachine and @endstatemachine

	# CommentBlocks is details of where the comment blocks are

	SwitchRE = re.compile(r'^(?P<indent>\s*)switch\s*\(\s*(?P<state>\S+?)\s*\)')
	CaseRE = re.compile(r'^\s*case\s+(?P<label>' + iskeyword + r'+):')
	StateVariableRE = re.compile(r'^\s*@state\s+(?P<state>\S+)')

	StateMachineLines = []
	StateMachineCases = []
	StateVariables = []
	InternalSwitch = False
	SwitchFound = False
	CurrentCase = None
	RemainingCode = None
	FoundStateMachine = False
	InitialLines = []
	GlobalStates = []

	for LineNumber in range(StateMachinePositions['Start'], StateMachinePositions['End']+1):
		ThisLine = lineArray[LineNumber]

		if ThisLine.find('@statemachine') != -1:
			FoundStateMachine = True

		if not FoundStateMachine:
			StateMachineLines.append(ThisLine)
			continue

		(Code, Comment) = SplitLine(ThisLine, LineNumber, CommentBlocks)
		#print "=================+"
		#print ThisLine
		#print "Comment: " + str(Comment)
		#print "Code:    " + str(Code)

		# Process Comment Parts
		if Comment is not None:
			Comment = Comment.strip()
			while Comment.startswith('*'):
				Comment = Comment[1:].strip()

			# If we haven't reached the switch line, check for state variables
			if not SwitchFound:
				m = StateVariableRE.match(Comment)
				if m is not None:
					StateVariables.append(m.group('state'))

				m = StateAddRE.match(Comment)
				if m is not None:
					GlobalStates.append(m.group('statename'))
					InitialLines.append(m.group('statename') + ' [label=' + m.group('label') + '];')

			# If this is the end line, we need to write out the real code
			# (all on one line)
			if Comment.find('@endstatemachine') != -1:
				if CurrentCase is not None:
					StateMachineCases.append(CurrentCase)

				DotGraph = ProcessStateCases(StateMachineCases, GlobalStates, InitialLines)
				
				# Add the DotGraph with appropriate comment surrounds
				if IsCommentBlockStart(LineNumber, CommentBlocks) and IsCommentBlockEnd(LineNumber, CommentBlocks):
					StateMachineLines.append(Code + "/** " + DotGraph + " */")
				elif IsCommentBlockStart(LineNumber, CommentBlocks):
					StateMachineLines.append(Code + DotGraph)
				elif IsCommentBlockEnd(LineNumber, CommentBlocks):
					StateMachineLines.append(DotGraph + Code)
				else:
					StateMachineLines.append(DotGraph)
				continue

			if CurrentCase is not None and len(Comment) > 0:
				CurrentCase['CommentLines'].append(Comment)

		# Process Code Parts
		if Code is not None:
			# No code processing until the switch statement is found
			if not SwitchFound:
				m = SwitchRE.match(Code)
				if m is not None:
					SwitchFound = True
					StateVariables.append(m.group('state'))
				StateMachineLines.append(Code)
				continue


			if InternalSwitch:
				if RemainingCode is not None:
					if BraceLevel is None and RemainingCode.count('{') > 0:
						BraceLevel = RemainingCode.count('{') - RemainingCode.count('}')
					elif BraceLevel is not None:
						BraceLevel += RemainingCode.count('{') - RemainingCode.count('}')
					RemainingCode = None

				if BraceLevel is None and Code.count('{') > 0:
					BraceLevel = Code.count('{') - Code.count('}')
				elif BraceLevel is not None:
					BraceLevel += Code.count('{') - Code.count('}')

				if BraceLevel == 0:
					InternalSwitch = False
			else:
				m = SwitchRE.match(Code)
				if m is not None:
					RemainingCode = Code[m.end():]
					InternalSwitch = True
					BraceLevel = None

				m = CaseRE.match(Code)
				if m is not None:
					if CurrentCase is not None:
						StateMachineCases.append(CurrentCase)
						CurrentCase = \
								{ \
									'State': m.group('label'),
									'FollowingStates': [],
									'OtherStates': [],
									'CommentLines': [],
									'InitialCase': False
								}
					else:
						CurrentCase = \
								{ \
									'State': m.group('label'),
									'FollowingStates': [],
									'OtherStates': [],
									'CommentLines': [],
									'InitialCase': True
								}

					StateChangeREs = []
					for StateVariable in StateVariables:
						StateChangeRegExpString = r'^\s*' + EscapeForRegExp(StateVariable) + \
								r'\s*=\s*(?P<state>' + iskeyword + r'+)\s*;'
						StateChangeRE = re.compile(StateChangeRegExpString)
						StateChangeREs.append(StateChangeRE)


			if CurrentCase is None:
				StateMachineLines.append(Code)
				continue

			m = StateChangeREs[0].match(Code)
			if m is not None:
				CurrentCase['FollowingStates'].append(m.group('state'))
			else:
				for StateChangeRE in StateChangeREs[1:]:
					m = StateChangeRE.match(Code)
					if m is not None:
						CurrentCase['OtherStates'].append(m.group('state'))

		if Code is None:
			Code = ""
		StateMachineLines.append(Code)


	return StateMachineLines

def StateMachineHandler(lineArray, options):
	"""Top level state machine handler.

	Find the lines containing state machine implementations and pass them
	onto the detailed handler.
	"""
	return BlockHandler(lineArray, options,
			StartDelimiter='@statemachine',
			EndDelimiter='@endstatemachine',
			Processor=ProcessStateMachine)
	
if __name__ == "__main__":
	# Parse command line
	from doxygen_preprocessor import CommandLineHandler
	options, remainder = CommandLineHandler()

	from filterprocessor import FilterFiles
	FilterFiles([StateMachineHandler,], options, remainder)

# vim:encoding=utf-8

