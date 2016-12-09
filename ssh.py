#!/usr/bin/env python

'''Login to remote machine to run commands
   By Adam Ho
'''

from __future__ import print_function

from __future__ import absolute_import

import pexpect
import sys, getpass


try:
	raw_input
except NameError:
	raw_input = input


USAGE = '''passmass host1 host2 host3 . . .'''
COMMAND_PROMPT = '[$#] '
TERMINAL_PROMPT = r'Terminal type\?'
TERMINAL_TYPE = 'vt100'
SSH_NEWKEY = r'Are you sure you want to continue connecting \(yes/no\)\?'

def login(host, user, password):

	child = pexpect.spawn('ssh -l %s %s'%(user, host))
	fout = file ("LOG.TXT","wb")
	child.logfile_read = fout #use child.logfile to also log writes (passwords!)

	i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[Pp]assword: '])
	if i == 0: # Timeout
		print('ERROR!')
		print('SSH could not login. Here is what SSH said:')
		print(child.before, child.after)
		sys.exit (1)
	if i == 1: # SSH does not have the public key. Just accept it.
		child.sendline ('yes')
		child.expect ('[Pp]assword: ')
	child.sendline(password)
    # Now we are either at the command prompt or
    # the login process is asking for our terminal type.
	i = child.expect (['Permission denied', TERMINAL_PROMPT, COMMAND_PROMPT])
	if i == 0:
		print('Permission denied on host:', host)
		sys.exit (1)
	if i == 1:
		child.sendline (TERMINAL_TYPE)
		child.expect (COMMAND_PROMPT)
	return child


def scp(path, username, hostname, password, targetpath):
	try:
		cmd = 'scp -r '+path+' '+username+'@'+hostname+':'+targetpath;
		child = pexpect.spawn(cmd)

		i = child.expect(["Password:", pexpect.EOF])

		if i==0:
			child.sendline(password)
			child.expect(pexpect.EOF)
		else:
			print 'errrrror'
	except Exception as e:
		print(e)


def run_cmds(host, user, password, cmds):
	try:
		child = login(host, user, password)
		if child == None:
			print('Could not login to host:', host)
		
		print('Successfully logged into host %s. Now run commands.'%(host))

		for cmd in cmds:
			child.sendline(cmd)
			child.expect(COMMAND_PROMPT)

		print ('Finished all jobs and exiting')
		child.sendline('exit')
	except Exception as e:
		print('Failed to run commands on host %s'%(host))
		print(e)
#test:
#run_cmds('ioteye-agent019', 'ioteye', 'ioteye1234', ['mkdir aaaaaaa'])