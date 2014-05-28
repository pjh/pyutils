# Python utility and helper methods.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from bisect import *
#from vm_regex import *
import io
import os
import re
import shlex
import string
import subprocess
import sys
import time

# Constants:
DEBUG = True
#DEBUG = False

def print_debug(tag, msg):
	if DEBUG:
		print('DEBUG: {0}: {1}'.format(str(tag), str(msg)))

# Special debugging method for debugging bug in vmsize plots...
def debug_vmsize_old(tag, pid, msg):
	debugthis = False
	if debugthis and (pid is None or pid in [15717, 14227, 15717]):
		print('VMSIZE: {}: {}'.format(str(tag), str(msg)))

def debug_vmsize(tag, msg):
	if False:
		tag = "VMSIZE: {}".format(tag)
		print_debug(tag, msg)

def debug_ignored(tag, msg):
	if True:
		tag = "IGNORE: {}".format(tag)
		#tag = "IGNORE: ".format()
		print_debug(tag, msg)

def debug_count(tag, msg):
	if False:
		tag = "COUNT: {}".format(tag)
		print_debug(tag, msg)

# Same as print_debug, but takes an initial enable argument, which
# is intended to be enabled/disabled on a per-method basis.
def print_debug2(enable, tag, msg):
	if DEBUG and enable:
		print('DEBUG: {0}: {1}'.format(str(tag), str(msg)))

def print_if_match(tag, key, expected, msg):
	if key == expected:
		print('DEBUG: {0}: {1}'.format(str(tag), str(msg)))

def abort_if_match(tag, key, expected):
	if key == expected:
		print_error_exit(tag, "aborting")

def print_warning(tag, msg):
	print('WARNING: {0}: {1}'.format(str(tag), str(msg)))

def print_error(tag, msg):
	print('ERROR: {0}: {1}'.format(str(tag), str(msg)))

def print_TODO(tag, msg):
	print('TODO: {0}: {1}'.format(str(tag), str(msg)))

def print_error_exit(tag, msg):
	print('ERROR: {0}: {1} - exiting.'.format(str(tag), str(msg)))
	sys.exit(1)

# If strict is True, then this method will print the error message and
# then abort. If strict is false, then this method will just print a
# warning and return.
def print_unexpected(strict, tag, msg):
	if strict:
		print_error_exit(tag, msg)
	else:
		print_warning(tag, msg)
	return

# Executes a command and saves its output and error streams to the
# specified files.
# This function doesn't do any error checking or timeout cautiousness.
# Returns: the return code of the executed command line.
#
# Does this method work with commands that have a pipe in them? I don't
# know yet...
def exec_cmd_save_output(cmdline, output_fname, err_fname):
	tag = "exec_cmd_save_output"

	# subprocess.call: runs the command described by the args, waits for
	# the command to complete, and returns a returncode.
	fout = open(output_fname, 'w')
	if not err_fname:
		ferr = None
	elif err_fname != output_fname:
		ferr = open(err_fname, 'w')
	else:
		ferr = fout
	retcode = subprocess.call(cmdline, shell=True, stdout=fout, stderr=ferr)
		# I think shell=True is needed for pipes to work
		# Note: shell=True is a security hazard!!
	#args = shlex.split(cmdline)
	#retcode = subprocess.call(args, shell=True, stdout=fout, stderr=ferr)
		# Note: when shell=True is used, cmdline string must be used,
		# rather than array of args! Otherwise, just the first arg is
		# executed.

	fout.close()
	if err_fname and err_fname != output_fname:
		ferr.close()
	return retcode

'''
If return code is non-zero, prints error but does not exit.
'''
def exec_cmd_wait(cmdline):
	tag = 'exec_cmd_wait'
	args = shlex.split(cmdline)
	#print_debug(tag, 'args={0}'.format(args))
	p = subprocess.Popen(args)
	retcode = p.wait()
	if retcode != 0:
		print('ERROR: command \"{0}\" returned {1}'.format(
				cmdline, str(retcode)))
	return retcode

'''
If return code is non-zero, prints error but does not exit.
'''
def exec_cmd_with_pipe(cmdline):
	tag = 'exec_cmd_with_pipe'
	#print_debug(tag, 'args={0}'.format(args))
	p = subprocess.Popen(cmdline, shell=True)
	retcode = p.wait()
	if retcode != 0:
		print('ERROR: command \"{0}\" returned {1}'.format(
				cmdline, str(retcode)))
	return retcode

# Executes the specified command (a single string) and returns its
# stdout and stderr. An optional env dictionary can be specified
# (e.g. for commands that need an additional DISPLAY value - use
# "os.environ.copy()" to make a copy of the current environment,
# then insert the new env['DISPLAY'].).
# The command must not contain and pipes or redirects, because this
# method does not execute the command in shell mode.
# Returns a tuple: (retcode, stdout, stderr), where stdout and stderr
# are strings, possibly containing newlines if there were multiple lines
# of std output / error, or possibly with len 0 if there was no std
# output / error.
def exec_cmd_get_output(cmd, env=None):
	tag = 'exec_cmd_return_lines'

	args = shlex.split(cmd)
	print_debug(tag, ("executing args: {}").format(args))

	p = subprocess.Popen(args, stdout=subprocess.PIPE,
			stderr=subprocess.PIPE, env=env)
	pipe_out = None
	pipe_err = None
	while pipe_out is None and pipe_err is None:
		(pipe_out, pipe_err) = p.communicate()
	retcode = p.wait()  # don't leave zombie processes!

	# Convert bytes to string. strip() will remove any superfluous
	# whitespace / newlines at end of output. After this command,
	# stdout and stderr are strings, possibly with several newlines
	# due to multiple lines of std output / error, or possibly with
	# len 0 if there was no outpt / error.
	stdout = pipe_out.decode('utf-8').strip()
	stderr = pipe_err.decode('utf-8').strip()

	return (retcode, stdout, stderr)

'''
usrgrp can be either "user" OR "user:group" - either will work directly with
the chown command below.
'''
def set_owner_group(output_dir, usrgrp):
	tag = "set_owner_group"

	# Recursively change the ownership of all of the files that we just
	# created in the output directory.
	cmd = ("chown -R {0} {1}").format(usrgrp, output_dir)
	exec_cmd_wait(cmd)

	return

def hex_no_X(hexint):
	return hex(hexint)[2:]

# Default width: 16 hex characters = 64-bit
def hex_zfill(hexint, width=16):
	return '0x' + (hex(hexint)[2:]).zfill(width)

# SORTED LIST functions: copied from
# http://docs.python.org/3/library/bisect.html#module-bisect. Note that
# lookups in the sorted list are O(log n), but insertions are still O(n)
# time.
def sl_verify_is_sorted(a):
	'Abort if list is not actually sorted in increasing order.'
	for i in range (1, len(a)):
		if a[i-1] > a[i]:
			print_error_exit("verify_is_sorted", "a[{0}] = {1} is "
				"greater than a[{2}] = {3}!".format(
				i-1, a[i-1], i, a[i]))
	return

def sl_index(a, x):
	'Locate the leftmost value exactly equal to x'
	i = bisect_left(a, x)
	if i != len(a) and a[i] == x:
		return i
	raise ValueError

def sl_index_ge(a, x):
	'Find leftmost item greater than or equal to x, and return its index.'
	'Added by pjh.'
	i = bisect_left(a, x)
	if i != len(a):
		return i
	raise ValueError

def sl_contains(a, x):
	'Returns true if element x is present in list a. Added by pjh.'
	try:
		i = sl_index(a, x)
		return True
	except ValueError:
		return False

def sl_insert(a, x):
	'Insert into sorted list. If the item is already present in the list, '
	'another copy will be added. Returns the updated list. This method added '
	'by pjh.'
	# http://stackoverflow.com/questions/8024571/insert-an-item-into-sorted-list-python
	#i = bisect_left(a, x)
	#a.insert(i, x)
	insort_left(a, x)

	return a

def sl_find_lt(a, x):
	'Find rightmost value less than x'
	i = bisect_left(a, x)
	if i:
		return a[i-1]
	raise ValueError

def sl_find_le(a, x):
	'Find rightmost value less than or equal to x'
	i = bisect_right(a, x)
	if i:
		return a[i-1]
	raise ValueError

def sl_find_gt(a, x):
	'Find leftmost value greater than x'
	i = bisect_right(a, x)
	if i != len(a):
		return a[i]
	raise ValueError

def sl_find_ge(a, x):
	'Find leftmost item greater than or equal to x'
	i = bisect_left(a, x)
	if i != len(a):
		return a[i]
	raise ValueError

# Passes every item in the list of values to the hash function and returns
# a new dict whose keys are those returned by the hash function, and whose
# values are *lists* of items from the value_list that hash to that key.
#   New feature: the hash_fn should return a LIST of keys, rather than
#   just a single key - this function will then iterate over the list of
#   keys and insert the value into the value-list for each key. This
#   allows a single value in the list to be inserted into multiple
#   slots / "categories" / keys in the constructed dict.
# If the hash_fn returns None for some item, then that item will not be
# included in the newly constructed dict!
# The dict that is returned may be empty, but None should never be returned.
# 
# Update: the return value is now a tuple, (newdict, total): where the
# total is the number of items in the value_list for which the hash_fn
# returned non-None. This total should be suitable for calculating
# percentages of the "total number of items in the list that we care about";
# this number is NOT exactly the number of items in the lists returned in
# the new dict, because items may now be inserted into multiple lists.
def construct_dict_from_list(value_list, hash_fn):
	tag = "construct_dict_from_list"

	#print_debug(tag, ("VALIDATE: len(value_list) == {0} vmas").format(
	#	len(value_list)))

	total = 0
	new_dict = dict()
	for item in value_list:
		# Note: need to make lists, can't just do
		#    new_dict[hash_fn(item)] = item !!
		keylist = hash_fn(item)
		if keylist:
			if type(keylist) != list:   # sanity check
				print_error_exit(tag, ("type returned from hash fn must "
					"now be a list of keys, not just a single key! "
					"keylist is {}, type is {}").format(keylist,
					type(keylist)))
			if len(keylist) > 0:
				total += 1   # count just once per non-empty keylist!
			for key in keylist:
				try:
					dict_list = new_dict[key]
				except KeyError:
					dict_list = list()
					new_dict[key] = dict_list
				dict_list.append(item)
	
	#if DEBUG:
	#	for key in new_dict.keys():
	#		print_debug(tag, ("VALIDATE: constructed dict key={0}, length "
	#			"of value list={1}").format(key, len(new_dict[key])))

	return (new_dict, total)

# Wrapper around construct_dict_from_list() that constructs the value_list
# from the values currently in an existing dictionary.
# IMPORTANT: make sure that the values in the dict_ are actually individual
# items that make sense to pass to the hash_fn, and are not, say, *lists*
# of items...
def construct_dict_from_dict(dict_, hash_fn):
	return construct_dict_from_list(dict_.values(), hash_fn)

# Returns the next line in the file, or '' if the end of the file has
# already been reached (important: '', *not* None), without advancing
# the position in the file.
def peek_next_line(openfile):
	# http://docs.python.org/3/library/io.html
	pos = openfile.tell()
	line = openfile.readline()
	openfile.seek(pos)
	return line

# Removes weird characters from the string so that it can be used as
# a filename. Acts "conservatively": most of the weird characters
# that are removed are actually valid for Unix.
def sanitize_fname(s, spaces_ok):
	# http://stackoverflow.com/a/295146/1230197
	valid_chars = "-_.()%s%s" % (string.ascii_letters, string.digits)
	if spaces_ok:
		valid_chars += ' '
	return ''.join(c for c in s if c in valid_chars)

# Don't forget to do 'null.close()' after you're done!
def get_dev_null():
	return open('/dev/null', 'w')

# Saves the system's current process tree to a new file at fname.
# If the file already exists, it will be overwritten!
def save_pstree(fname):
	tag = "save_pstree"

	# subprocess.call: runs the command described by the args, waits for
	# the command to complete, and returns a returncode.
	f = open(fname, 'w')
	cmdline = "pstree -pl"   # -l needed, or not everything is included!
	args = shlex.split(cmdline)
	retcode = subprocess.call(args, stdout=f, stderr=f)
	if retcode != 0:
		print_warning(tag, ("command \"{0}\" returned non-zero code "
			"{1}").format(args, retcode))
	f.close()
	return

# Copies the /proc/pid/fname file to destname. Needs passwordless sudo!
# After copying, the owner and group are set to the currently logged
# in user's name and group (so the file does not end up owned by
# root:root).
# Returns: False if the copy [cat] command failed, True if it succeeded.
def copy_proc_file(pid, fname, destname):
	tag = 'copy_proc_file'

	srcname  = "/proc/{}/{}".format(pid, fname)
	user = os.geteuid()
	group = os.getegid()
	
	cmdline = ("sudo bash -c 'cat {} > {}; chown {}:{} {}'").format(
			srcname, destname, user, group, destname)
	args = shlex.split(cmdline)
	retcode = subprocess.call(args)
	if retcode != 0:
		print_error(tag, ("command \"{}\" returned non-zero code "
			"{}").format(cmdline, retcode))
		return False

	return True

# Calls .close() on every file in the list
def close_files(filelist):
	for f in filelist:
		f.close()
	return

# Returns a list of files in the tree rooted at rootdir whose filename
# is the same as name (or whose filename contains name if exactmatch is
# set to False). One or both of findfiles and finddirs must be set to
# True or this method will always return an empty list.
# By default, simlinks will not be followed unless followlinks is set
# to True (which causes risk of infinite recursion - use carefully).
# If absdirs is set to True, then absolute directories will be returned,
# otherwise the directories will be relative to the $PWD.
#
# WARNING: as of October 20, this method is only very lightly tested!
def find_files_dirs(rootdir, name, exactmatch=True, findfiles=False,
		finddirs=False, followlinks=False, absdirs=False):
	tag = 'find_files_dirs'

	if not findfiles and not finddirs:
		print_err(tag, "neither findfiles nor finddirs is set! Returning []")
		return []

	# http://docs.python.org/3/library/os.html#os.listdir
	# http://docs.python.org/3/library/os.html#os.walk
	#   For each directory in the tree rooted at directory top (including
	#   top itself), it yields a 3-tuple (dirpath, dirnames, filenames).
	# That is, os.walk will walk the entire subtree, not just the first
	# level of the subtree.
	foundfiles = []
	for root, dirs, files in os.walk(rootdir, followlinks=followlinks):
		if findfiles:
			for f in files:
				if ((exactmatch and f == name) or
						(not exactmatch and name in f)):
					if absdirs:
						path = os.path.abspath(root)
					else:
						path = root
					filename = "{}/{}".format(path, f)
					foundfiles.append(filename)
		if finddirs:
			# Check against dirs, not against each root, because root
			# will include the full path, whereas d in dirs is just the
			# directory's name itself (so we can check it against the
			# target name).
			for d in dirs:
				if ((exactmatch and d == name) or
						(not exactmatch and name in d)):
					if absdirs:
						path = os.path.abspath(root)
					else:
						path = root
					dirname = "{}/{}".format(path, d)
					foundfiles.append(dirname)

	return foundfiles

# Writes a vim modeline to the open writable file passed as an argument
# TODO: implement commentstyle to write appropriate comment formatting for
# python files, C files, etc.
def write_vim_modeline_nowrap(f, commentstyle=None):
	# http://vim.wikia.com/wiki/Modeline_magic
	f.write('# vim: set nowrap:\n')
	return

# Finds all the children of the specified target_pid, using the "ps"
# command. If direct_children_only is set to False, then all child pids
# in the hierarchy under the target pid will be returned; if set to
# True, then only the direct children (and not their children) will be
# returned. An output filename must be specified because this command
# works by saving the ps output to a file, then reading it back in.
# "ps_hierarchy" will be appended to the output_prefix.
#
# This method is somewhat fragile; it depends on the output of a
# particular command being formatted in the expected way.
# 
# Returns: a [list] of the pids of all of the processes that are children
# of the strace process called by this python script. The pids in the
# list are kept in the order they are encountered in the ps output.
# If the target_pid is not found, or if no children are found, an empty
# list will be returned. None is returned on error.
def find_children_of_pid(target_pid, direct_children_only, output_prefix):
	tag = "find_children_of_pid"

	# Note: the python "multiprocessing" package has a function called
	# "active_children()", but I'm pretty sure that it can only be used
	# to get child processes that were started explicitly by this script
	# using the other methods in that package - I tried and it doesn't
	# return the children of a process started with Popen(), etc.

	cmdline = "ps -eHo pid,pgid,comm"
	pscmd_line = re.compile(
		r"^\s*(?P<pid>[0-9]+)\s+(?P<pgid>[0-9]+)(?P<spaces> +)(?P<cmd>\S+.*)$")
	
	fname = "{}-ps_hierarchy".format(output_prefix)
	retcode = exec_cmd_save_output(cmdline, fname, fname)
	if retcode != 0:
		print_warning(tag, ("got back non-zero retcode {} from "
			"exec_cmd_save_output()").format(retcode))
		return None

	# The hierarchy will look like this:
	#   ...
	#    1124  1124           python3
	#    1172  1124             chromedriver
	#    1175  1124               chrome
	#    1182  1124                 chrome
	#    1183  1124                 chrome-sandbox
	#    1184  1124                   chrome
	#    1188  1124                     nacl_helper
	#    1189  1124                     chrome
	#    1278  1124                       chrome
	#    1344  1124                       chrome
	#    1384  1124                       chrome
	#    1352  1124                 chrome
	#    1356  1124                   chrome
	#   ...

	ps = open(fname, 'r')
	state = 'header'
	indent = 0
	prev_indent = None
	target_indent = None
	children = []

	while True:
		prev_indent = indent
		line = ps.readline()
		if not line:
			break
		match = pscmd_line.match(line)
		if not match:   # e.g. header line
			if state != 'header':
				print_error_exit(tag, ("failed to match ps line! {}").format(
					line))
			else:
				state = 'find_target'
				continue
		
		pid = int(match.group('pid'))
		pgid = int(match.group('pgid'))
		indent = len(match.group('spaces'))
		cmd = match.group('cmd')

		if pid == target_pid:
			target_indent = indent + 2
			state = 'found_target'
			#print_debug(tag, ("set target_indent={} after finding line "
			#	"matching target_pid {}: {}").format(target_indent,
			#	target_pid, line))
			continue
		elif state == 'found_target':
			# At this point, if we've found the target pid line, we only
			# want to continue searching while the indent is >= the
			# target_indent; if the indent drops to less than the
			# target_indent, then we're looking at processes that are no
			# longer part of the target's hierarchy, so we're done.
			if indent >= target_indent:
				if not direct_children_only:
					#print_debug(tag, ("found line with indent {} >= "
					#	"target_indent, adding pid {} to children").format(
					#	indent, pid))
					children.append(pid)
				elif indent == target_indent:
					#print_debug(tag, ("found line with indent {} == "
					#	"target_indent, adding pid {} to children").format(
					#	indent, pid))
					children.append(pid)
			else:
				#print_debug(tag, ("indent {} < target_indent {}, "
				#	"breaking out of loop").format(indent, target_indent))
				break
		# loop again
	
	ps.close()

	if state == 'find_target':
		print_warning(tag, ("target_pid {} not found in ps output!").format(
			target_pid))
		return []
	
	return children

# Tries to call p.kill on every Popen process in the list passed as 
# an argument. If one of the processes has already terminated, it is
# handled gracefully (ignored).
def kill_Popens(p_list):
	for p in p_list:
		try:
			p.kill()
		except ProcessLookupError:
			pass
	return

B_BYTES = 1
KB_BYTES = 1024
MB_BYTES = 1024 * 1024
GB_BYTES = 1024 * 1024 * 1024
TB_BYTES = 1024 * 1024 * 1024 * 1024
SCALE_TO_LABEL = {
		 B_BYTES	:	 'B',
		KB_BYTES	:	'KB',
		MB_BYTES	:	'MB',
		GB_BYTES	:	'GB',
		TB_BYTES	:	'TB',
	}

def pretty_bytes(bytes_, decimals=3):
	if bytes_ < KB_BYTES:
		label = 'B'
		num = str(bytes_)
	elif bytes_ < MB_BYTES:
		label = 'KB'
		num = "{0:.{1}f}".format(bytes_ / KB_BYTES, decimals)
	elif bytes_ < GB_BYTES:
		label = 'MB'
		num = "{0:.{1}f}".format(bytes_ / MB_BYTES, decimals)
	elif bytes_ < TB_BYTES:
		label = 'GB'
		num = "{0:.{1}f}".format(bytes_ / GB_BYTES, decimals)
	else:
		label = 'TB'
		num = "{0:.{1}f}".format(bytes_ / TB_BYTES, decimals)

	return ("{0} {1}").format(num, label)

def to_percent(floatval, numplaces):
	return "{:.{prec}%}".format(floatval, prec=numplaces)

# Creates a file at the specified destination, then writes the lines in the
# list to the file and closes it. App-specific app_to_measure objects should
# set up the lines for their configuration etc. files, then call this helper
# method to write those lines to a file.
#
# The destination file should be located in the measurement output
# directory so that it can be examined later to see exactly what was run
# when the application was measured!
def write_conf_file(lines, dest_fname, overwrite=False):
	tag = 'write_conf_file'

	if os.path.exists(dest_fname):
		if overwrite:
			print_warning(tag, ("dest_fname {} already exists, will "
				"overwrite it").format(dest_fname))
		else:
			print_error_exit(tag, ("dest_fname {} already exists").format(
				dest_fname))
	dest_f = open(dest_fname, 'w')

	for line in lines:
		dest_f.write("{}\n".format(line))
	dest_f.close()

	return

# Applies uniq_fn to every element of the input list to determine the
# unique elements of the list. Then, a new list containing only unique
# members is constructed and returned - the elements of the returned
# list will have the uniq_fn applied as well! The input list is not
# modified.
# If uniq_fn is None, then the identity function will be used.
def list_uniq(L, uniq_fn):
	tag = 'list_uniq'

	if not uniq_fn:
		uniq_fn = lambda x: x

	listcopy = list(L)
	uniqlist = map(uniq_fn, listcopy)
	
	# http://stackoverflow.com/a/480227/1230197
	seen = set()
	seen_add = seen.add
	retlist = [ x for x in uniqlist if x not in seen and not seen_add(x)]

	return retlist

# Returns the index of target in SORTED list L. If target is not found
# and exact is True, then -1 is returned; if exact is False,
# then the index of the greatest element less than target is returned
# (-1 if the target is less than all of the elements in the list).
# If key is specified, then the key method will be applied to the
# elements in the list before comparing them to target (the key method
# is NOT applied to target itself). If key is not specified, then the
# items in the list must be comparable!
def binarysearch(L, target, key=None, exact=True):
	tag = 'binarysearch'

	if L is None or len(L) == 0:
		return -1
	if key is None:
		key = lambda x: x
	
	# Modified version of https://en.wikibooks.org/wiki/
	# Algorithm_Implementation/Search/Binary_search#Python
	lo = 0
	hi = len(L) - 1
	while lo <= hi:
		mid = int((lo + hi) / 2)
		if key(L[mid]) < target:
			lo = mid + 1
		elif target < key(L[mid]):
			hi = mid - 1
		else:
			return mid

	if not exact:
		# mid is the index that we just looked at; if we just looked
		# at a value less than the target, then it should be the
		# inexact match we're looking for. Otherwise, we just looked
		# at a value just-greater-than the target, so subtract 1
		# from that index.
		# I'll be honest, I only thought this through very quickly,
		# but did tests with sorted lists of ints with length 0->3
		# and the inexact match seemed to always work.
		if key(L[mid]) < target:
			return mid
		else:
			return mid - 1

	return -1

# Uses pgrep to search for processes named exactly 'name', and if any
# are running, attempts to kill them using SUDO kill -9. Note that
# the name is case-sensitive!
# If the sleeptime argument is provided, then this method will wait
# that many seconds between the pkill and the final pgrep to see if
# the pkill worked or not.
# Returns True if all such processes were killed successfully (or
# if none existed), or False if the kill did not work.
def pgrep_pkill(name, sleeptime=0):
	tag = 'pgrep_pkill'

	grepcmd = "pgrep -x {}".format(name)
	(retcode, out, err) = exec_cmd_get_output(grepcmd)
	if retcode == 0 or len(out) > 0:
		# when pgrep finds nothing, its retcode should be 1
		print_warning(tag, ("\"pgrep {}\" returned code {} and "
			"output {} - there are already {} processes running, "
			"so attempting to kill them now.").format(name,
			retcode, out, name))
		killcmd = "sudo bash -c 'pkill -9 -x {}'".format(name)
		args = shlex.split(killcmd)
		retcode = subprocess.call(args)
		
		time.sleep(sleeptime)
		(retcode, out, err) = exec_cmd_get_output(grepcmd)
		if retcode == 0 or len(out) > 0:
			print_error(tag, ("failed to kill running {} processes "
				"{}, returning now").format(name, out))
			return False
	
	return True

if __name__ == '__main__':
	print_error_exit("not an executable module")

