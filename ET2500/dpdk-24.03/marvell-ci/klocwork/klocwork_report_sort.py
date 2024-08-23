#!/usr/bin/python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Marvell
import sys

if len(sys.argv) < 3:
	print("Usage klockwork_report_sort.py <src_dir_path> <klocworkreport>")
	exit(1)

src_path = sys.argv[1]

# Read the lines
kwreport = open(sys.argv[2], 'r')
lines = kwreport.readlines()
kwreport.close()

# Remove the summary lines
lines = lines[:len(lines) - 2]

issues = {}
issue_begin = False
for line in lines:
	line = line.strip()

	if line == "---------------------------------------------------------------------------":
		issue_begin = True
		continue

	if issue_begin:
		issue_num = line.split()[0]
		line = ' '.join(line.split()[1:])
		issue_desc = line + " " + issue_num
		line = line.replace(src_path, '')
		issues[issue_desc] = []
		issue_begin = False

	issues[issue_desc].append(line)


for key in sorted(issues):
	print("---------------------------------------------------------------------------")
	for line in issues[key]:
		print(line.strip())

print("\nTotal Issue(s) %d" % len(issues))
