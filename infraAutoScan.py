import time, yaml, os, importlib, logging, datetime, requests, sys
import modules.utilitat as utilitat
from datetime import date
from pathlib import Path

logger = logging.getLogger(__name__)

def create_project_dir(projectDir,resultsDir,scansDir,projectName):
	logging.info('Create project folders')
	if not projectDir:
		projectDir = os.getcwd()
	
	# Project
	projectDir = utilitat.new_folder(projectDir,projectName)

	# Results
	resultsDir = utilitat.new_folder(projectDir,resultsDir)

	# Scans
	scansDir = utilitat.new_folder(projectDir,scansDir)

	return projectDir,resultsDir,scansDir

def checkConf(globalConf):
	logger.info('Check configuration file')
	error = 0
	msg = ''

	# Check authentication
	if globalConf['ScanType']['Auth']:
		if globalConf['Authentication']['Token']:
			logger.info('	- Authenticated scan: {}'.format(globalConf['Authentication']['Token']))
		elif globalConf['Authentication']['Cookie']:
			logger.info('	- Authenticated scan: {}'.format(globalConf['Authentication']['Cookie']))
		else:
			error = 1
			msg += '    - Authentication method not specified\n'
			logger.error('Authentication method not specified')
	# Check dirs empty
	for key in globalConf.keys():
		if 'Dir' in key and key != 'ProjectDir':
			if not globalConf[key]:
				error = 1
				msg += '    - {} not defined\n'.format(key)
	# Check Scope
	if not globalConf['Scope']:
		error = 1
		msg += '    - Scope not defined\n'
	file = Path(globalConf['Scope'])
	if not file.is_file():
		error = 1
		msg += '    - Scope file not found in {}\n'.format(globalConf['Scope'])
	if os.path.getsize("scope.txt") == 0:
		print("    - Scope file is empty\n")
	
	# Check programs (dig for testssl)

	if error:
		print ('[!] Check the configuration file:')
		print (msg)
		exit(0)

def change_permisions(projectDir,logsName,user):
	logger.info('Change permissions')
	cmd = 'chown -R {}:{} {}'.format(user,user,projectDir)
	r = utilitat.execute(cmd,'DEVNULL','DEVNULL')

	#logsDir = os.path.join(rootDir,logsName)
	cmd = 'chown -R {}:{} {}'.format(user,user,logsName)
	r = utilitat.execute(cmd,'DEVNULL','DEVNULL')
	

if __name__ == '__main__':
	# The check is just for installaton requirements script to verify no dependencies are left wihtout executing the scans
	check = ''
	try:
		check = sys.argv[1]
	except:
		pass
	if check:
		print ('Ready!')
		exit(0)
		
	if os.geteuid() != 0:
		print("[!] Some scripts need sudo to run. They might not execute.\n")
	print ('[i] infraAutoScan version 1.1')
	print ('\n[*] Init')
	print ('    - Load initial config')
	globalConf = utilitat.load_config('config/global.yaml')
	
	#utilitat.new_folder(globalConf['ProjectDir'],globalConf['LogsDir'])
	log = '{}/{}.log'.format(globalConf['LogsDir'],date.today().strftime("%d_%m_%Y"))
	logging.basicConfig(filename=log, level=logging.DEBUG, format='[%(levelname)s] %(asctime)s (%(filename)s): %(message)s', datefmt='%d/%m/%Y %I:%M:%S %p')

	logger.info('***************** Inici *****************')
	logger.info('***** Hora inici: {}'.format(datetime.datetime.now().strftime("%X/%d_%m_%Y")))

	print ('    - Load configuration file')
	checkConf(globalConf)

	print ('    - Create project folders')
	projectDir,resultsDir,scansDir = create_project_dir(globalConf['ProjectDir'],globalConf['ResultsDir'],globalConf['ScansDir'],globalConf['ProjectName'])

	print ('    - Load modules')
	modules = globalConf['Modules']
	
	for m in modules:
		module_name = list(m.keys())[0]
		if m[module_name]:
			module_dir = '{}.{}'.format(globalConf['ModulesDir'],module_name)
			try:
				module = importlib.import_module(module_dir)
			except Exception as e:
				logger.error(e)
			else:
				module.run(globalConf,scansDir,resultsDir)
	
	change_permisions(projectDir,globalConf['LogsDir'],globalConf['User'])

	logger.info('***** Hora fi: {}'.format(datetime.datetime.now().strftime("%X/%d_%m_%Y")))
	logger.info('***************** Fi *****************')