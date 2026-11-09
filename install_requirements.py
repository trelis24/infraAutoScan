import os, subprocess, shlex, apt, configparser
from pathlib import Path

def execute(cmd):
	r = ''
	stdout = subprocess.PIPE
	stderr = subprocess.PIPE
	try:
		r = subprocess.run(shlex.split(cmd),stdout=stdout,stderr=stderr)
	except Exception as e:
		print('Execute: {}'.format(e))

	return r.stdout.decode('utf-8'),r.stderr.decode('utf-8')

def apt_is_installed(name):
	cache = apt.Cache()
	cache.open()
	try:
		return cache[name].is_installed
	except KeyError:
		return False

def pip_is_installed(name):
	cmd = 'venv/bin/python3 -m pip show {}'.format(name)
	result,error = execute(cmd)
	if error:
		return False
	return True

def remove_apt(name):
	cmd = 'sudo apt remove -y {}'.format(name)
	result,error = execute(cmd)

def install_apt(name):
	print ('    - Install {}:'.format(name), end = " ")
	if not apt_is_installed(name):
		cmd = 'sudo apt install -y {}'.format(name)
		result,error = execute(cmd)
		if apt_is_installed(name):
			print ('Installed')
		else:
			print ('Error')
	else:
		print ('Already installed')

def install_pip(name):
	print ('    - Install {}:'.format(name), end = " ")
	if not pip_is_installed(name):
		cmd = 'venv/bin/python3 -m pip install {}'.format(name)
		result,error = execute(cmd)
		if pip_is_installed(name):
			print ('Installed')
		else:
			print ('Error')
	else:
		print ('Already installed')

def install_github(path,name,url):
	print ('    - Download {}:'.format(name), end = " ")
	cmd = 'git clone -q {}'.format(url)
	execute(cmd)
	
	folder = url.split('/')[-1].replace('.git','')
	cmd = 'sudo mv {} {}'.format(folder,path)
	execute(cmd)

	file = os.path.join(path,folder)
	cmd = 'ls {}'.format(file)
	result,error = execute(cmd)
	if error:
		print ('Error')
	else:
		print ('Installed')

def needrestart():
	lines = ''
	with open('/etc/needrestart/needrestart.conf', 'r') as file:
		lines = file.readlines()
	for i, line in enumerate(lines):
		if line.strip() == "#$nrconf{kernelhints} = -1;":
			lines[i] = "$nrconf{kernelhints} = -1;\n"
	with open('/etc/needrestart/needrestart.conf', 'w') as file:
		file.writelines(lines)


def load_apt(apt):
	print ('\n[*] Install APT requirements')
	for key in apt:
		install_apt(apt[key])

def load_pip(pip):
	print ('\n[*] Install PIP requirements')
	for key in pip:
		install_pip(pip[key])


def load_github(path,github):
	print ('\n[*] Download Github requirements')
	for key in github:
		install_github(path,key,github[key])

def check_scan():
	cmd = 'venv/bin/python3 infraAutoScan.py check'
	result,error = execute(cmd)
	if error:
		print ('\n[!] Some dependences missing!')
	else:
		print ('\n[*] Dependences installed. You can execute infraAutoScan.py with the following command:')
		print ('sudo venv/bin/python3 infraAutoScan.py')

if __name__ == '__main__':
	if os.geteuid() != 0:
		print("[!] Sudo required for installation.\n")
		execute('sudo ls')
	print ('[i] Requirements infraAutoScan version 1.0')

	# Virtual enviroment + yaml + pip in venv
	print ('\n[*] Init')
	print ('    - Remove unable to resolve sudo message')
	cmd = 'cat /etc/hostname'
	hostname,error = execute(cmd)
	with open("/etc/hosts", "a") as file:
		c = '127.0.0.1	{}'.format(hostname)
		file.write(c)
	print ('    - Remove pending kernel updates message')
	remove_apt('needrestart')
	install_apt('python3-virtualenv')
	print ('    - Create virtual enviroment')
	install_apt('python3-venv')
	cmd = 'python3 -m venv venv'
	execute(cmd)
	print ('    - Install pip in virtual enviroment')
	cmd = 'sudo venv/bin/python3 files/get-pip.py'
	result = execute(cmd)
	if not 'Successfully installed' in result:
		print ('\n[!] Error installing pip.')
		exit(0)

	print ('\n[*] Load initial config')
	config = configparser.ConfigParser()
	config.optionxform = str
	print ('    - Load requirements.conf')
	config.read('config/requirements.conf')

	load_apt(config['Apt'])

	load_pip(config['Pip'])

	load_github(config['Path']['Github'],config['Github'])

	check_scan()

