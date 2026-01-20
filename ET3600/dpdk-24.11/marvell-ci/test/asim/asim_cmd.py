#!/usr/bin/python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Marvell

import argparse
import itertools
import psutil
import nclib
import re
import signal
import socket
import string
import sys
import termios
import time
import tty

g_uart = ('localhost', 2000)
g_interactive = False
g_logfilepath = '/tmp/asim_cmd_uart.log'
g_nc = None
g_stdinattr = None

class nclogger(nclib.logger.Logger):
	def __init__(self, log_send=None, log_recv=None):
		self.log_send = log_send
		self.log_recv = log_recv

	def sending(self, data):
		if self.log_send is not None:
			self.log_recv.write(''.join(filter(lambda x: x in set(
				string.printable), data.decode(sys.stdout.encoding))))
			self.log_recv.flush()

	def buffering(self, data):
		if self.log_recv is not None:
			self.log_recv.write(''.join(filter(lambda x: x in set(
				string.printable), data.decode(sys.stdout.encoding))))
			self.log_recv.flush()


def nc_recv(nc, timeout):
	rsp = nc.recv_line(timeout=timeout).decode(sys.stdout.encoding)
	return rsp

def nc_drain(nc, timeout):
	while True:
		rsp = nc_recv(nc, timeout)
		if len(rsp) == 0:
			break

def nc_close(nc):
	if nc != None:
		nc_drain(nc, 2)
		nc.close()

def nc_send_cmd(nc, args):
	nc_drain(nc, 2)
	nc.send_line(str.encode(args))
	nc.send_line(str.encode(''))
	pat_fail = re.compile(r"ASIM_DP_fail")
	pat_succ = re.compile(r"ASIM_DP_success")
	pat_skip = re.compile(r"ASIM_DP_skip")
	# Although nclib has recv_until function it's not reliable,
	# use recv_line until we encounter 'ASIM_DP_*'
	full_rsp = ''
	while True:
		rsp = nc_recv(nc, 5)
		rsp = ''.join(filter(lambda x: x in set(string.printable), rsp))
		print(rsp, end = '')
		sys.stdout.flush()
		full_rsp = full_rsp + rsp
		match_succ = pat_succ.findall(full_rsp.strip())
		match_fail = pat_fail.findall(full_rsp.strip())
		match_skip = pat_skip.findall(full_rsp.strip())
		if len(match_succ):
			return 0
		if len(match_skip):
			return 77
		if len(match_fail):
			return 1
		# Trim the full response. We need to check only whether the pattern has got split
		# across the responses.
		full_rsp = full_rsp[-16:]

def nc_interact(nc):
	global g_interactive
	global g_stdinattr
	g_interactive = True
	try:
		stdin = sys.stdin.fileno()
		g_stdinattr = termios.tcgetattr(stdin)
		tty.setcbreak(stdin, termios.TCSANOW)
		nc.interact()
	except termios.error as e:
		pass
	except Exception as e:
		print("Caught " + str(e) + " in interactive mode")
		try:
			termios.tcsetattr(stdin, termios.TCSANOW, g_stdinattr)
		except:
			pass

def get_time():
	return time.perf_counter()

def get_time_elapsed(since):
	return get_time() - since

def nc_connect(logger, uart):
	print("Waiting for UART socket {} to come-up ".format(uart), end='')
	timeout = 10.0
	start_timer = get_time()
	prog_timer = get_time()
	while True:
		try:
			if get_time_elapsed(prog_timer) > 0.5:
				sys.stdout.write("#")
				sys.stdout.flush()
				prog_timer = get_time()
			nc = nclib.Netcat(uart, loggers=[logger])
			if nc:
				break
		except:
			time.sleep(0.2)
			if get_time_elapsed(start_timer) >= timeout:
				print('Wait timeout {}, failed to open port'.format(timeout))
				raise Exception("Failed to open port")
	print('done! {:3.2f}s'.format(get_time_elapsed(start_timer)))
	return nc

def asim_start_time():
	conns = psutil.net_connections(kind="inet4")
	asim_pid = 0
	for conn in conns:
		fd, family, _type, laddr, raddr, status, pid = conn
		ip, port = laddr
		if ip == socket.gethostbyname('localhost') and port == 2000:
			asim_pid = pid
			break
	asim = psutil.Process(asim_pid)
	return asim.create_time()

def nc_linux_prompt(nc, timeout, console):
	pat_ps1 = re.compile(console)
	timeout = 100.0 if timeout is None else timeout
	asim_start = asim_start_time()

	print("Waiting for {} prompt to come-up ".format(console), end='')
	start_timer = get_time()
	prog_timer = get_time()
	while True:
		try:
			if get_time_elapsed(prog_timer) > 0.5:
				sys.stdout.write("#")
				sys.stdout.flush()
				prog_timer = get_time()
			rsp = nc_recv(nc, 1)
			if len(rsp) == 0:
				if time.time() - asim_start < 180:
					continue
				nc.send_line(str.encode(''))
				continue
			match = pat_ps1.findall(
				''.join(filter(lambda x: x in set(string.printable), rsp)).strip())
			if len(match):
				# We reached the terminal YaY!!
				print('done! {:3.2f}s'.format(get_time_elapsed(start_timer)))
				nc.send_line(str.encode(''))
				break
			if get_time_elapsed(start_timer) >= timeout:
				print('Wait timeout {}, Linux prompt failed to come-up'.format(timeout))
				raise Exception("Linux prompt failed to come-up")
		except:
			break

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"--cmd", help="Command to send to UART console", type=str)
	parser.add_argument(
		"--console", help="Wait for Linux to come-up", nargs='?', type=str,
		const="ASIM_DP.*#")
	parser.add_argument(
		"--timeout", help="Time to wait for connection", type=int)
	args = parser.parse_args()
	return args

def sigint_handler(signum, frame):
	global g_nc
	global g_interactive
	if g_nc != None and g_interactive:
		g_nc.write('\x03')
		return
	print("Caught SIGINT in asim_cmd.py")
	nc_close(g_nc)
	sys.exit(signum)

def sig_handler(signum, frame):
	global g_nc
	global g_stdinattr
	print("Caught signal " + str(signum) + " in asim_cmd.py")
	nc_close(g_nc)
	if g_stdinattr:
		try:
			stdin = sys.stdin.fileno()
			termios.tcsetattr(stdin, termios.TCSANOW, g_stdinattr)
		except:
			pass
	sys.exit(signum)

if __name__ == "__main__":
	signal.signal(signal.SIGINT, sigint_handler)
	signal.signal(signal.SIGQUIT, sig_handler)
	signal.signal(signal.SIGTERM, sig_handler)
	args = parse_args()
	logfd = open(g_logfilepath, 'a+')
	logger = nclogger(log_send=logfd, log_recv=logfd)

	status = 0
	try:
		g_nc = nc_connect(logger, g_uart)
		if args.console:
			nc_linux_prompt(g_nc, args.timeout, args.console)
		if args.cmd:
			status = nc_send_cmd(g_nc, args.cmd)
		else:
			nc_interact(g_nc)
		nc_close(g_nc)
	except Exception as e:
		print(e)
		print('Failed to connect to {}. Please check if UART is running.'.format(g_uart))
		logfd.write('Failed to connect to {}'.format(g_uart))
		nc_close(g_nc)
		status = 1
	logfd.close()
	sys.exit(status)
