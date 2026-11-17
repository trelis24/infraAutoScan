import logging, os, re, json
import modules.utilitat as utilitat
from pathlib import Path

logger = logging.getLogger(__name__)

def run(globalConf,scansDir,resultsDir):
	logger.info('Run')
	print ('\n[*] Nuclei')

	config = utilitat.load_config('config/nuclei.yaml')
	nucleiDir = utilitat.new_folder(scansDir,config['FolderName'])

	nmapConf = utilitat.load_config('config/nmap.yaml')
	resultsNmap = os.path.join(resultsDir,nmapConf['FolderName'])
	nmapFolder = os.path.join(resultsNmap,'advanced_byService')

	run_nuclei(nucleiDir,config,nmapFolder,resultsDir,globalConf['User'])
	'''
	if r:
		results, resultsTestSSL = parse_results(testsslDir,resultsDir)
		ssl_tls_annex(results, resultsTestSSL)
	'''

def parse_results(testsslDir,resultsDir):
	print ('    - Parse results')
	logger.info('    - Parse results')
	resultsTestSSL = utilitat.new_folder(resultsDir,'testssl')
	file = os.path.join(testsslDir,'testssl.json')
	json_data = utilitat.read_json(file)
	results = parse_json(json_data)
	store_results(results, resultsTestSSL)
	return results, resultsTestSSL


def store_results(results, output_file):
	# JSON
	utilitat.write_json(results, output_file, 'testssl.json')

	# TXT
	file = os.path.join(output_file,'testssl.txt')
	with open(file, 'w') as o:
		for title in results.keys():
			data = '\n{}\n'.format(title.upper())
			o.write(data)
			if title == 'error':
				for ip in results[title]:
					data = '  {}\n'.format(ip)
					o.write(data)
			else:
				for category in results[title]:
					if results[title][category]:
						data = '  {}\n'.format(category)
						o.write(data)
						for ip in results[title][category]:
							data = '    {}\n'.format(ip)
							o.write(data)

def workflow_exists(tech):
    return (Path.home() / "nuclei-templates" / "workflows" / f"{tech}-workflow.yaml").is_file()

def run_nuclei(nucleiFolder,config,nmapFolder,resultsDir,user):
	logger.info('Run Nuclei')
	nmapFolder = Path(nmapFolder)
	nucleiFolder = Path(nucleiFolder)
	nucleiTemplates = Path(config['NucleiTemplates'])
	homePath = Path(f'home/{user}')
	resultsDir = Path(resultsDir)
	
	# Check workflows
	print ('    - Workflows')
	workflows = []
	for entry in nmapFolder.iterdir():
		tech = entry.stem if entry.is_file() else entry.name  
		workflow_path = homePath / nucleiTemplates / 'workflows' / f'{tech}-workflow.yaml'
		if workflow_path.is_file():
			workflow = {
				'tech':tech,
				'yaml':f'{tech}-workflow.yaml',
				'json':f'{tech}-workflow.json'
			}
			workflows.append(workflow)

	nucleiFolder = Path('scans\\nuclei\\')
	for workflow in workflows:
		print (f'        - {workflow["tech"]}')
		utilitat.new_folder(nucleiFolder,workflow['tech'])
		output = nucleiFolder / workflow['tech'] / workflow['json']
		nmap_ips = nmapFolder / workflow['tech'] / 'ip.txt'
		cmd = f"{homePath}/{config['Binary']} -l {nmap_ips} -w workflows/{workflow['yaml']} --silent -je {output}"

		try:
			utilitat.execute(cmd,nucleiFolder / workflow['tech'],workflow['tech'])
		except Exception as e:
			logger.error(e)

	
	# HTTP
	print ('    - HTTP services')
	utilitat.new_folder(nucleiFolder,'http')
	http_file = resultsDir / 'http.txt'
	output = nucleiFolder / 'http' / 'http.json'

	cmd = f"{homePath}/{config['Binary']} -l {http_file} -as --silent -je {output}"

	try:
		utilitat.execute(cmd,nucleiFolder / 'http','http')
	except Exception as e:
		logger.error(e)



	# Checks not included in http or workflows
	print ('    - Additional checks')
	utilitat.new_folder(nucleiFolder,'additional_checks')
	etags = ",".join(p.name for p in nucleiFolder.iterdir() if p.is_dir())
	hosts_up = resultsDir / 'nmap' / 'hosts_up.txt'


	print ('        - C2')
	output = nucleiFolder / 'additional_checks' / 'c2.json'
	cmd = f"{homePath}/{config['Binary']} -l {hosts_up} -t network/c2/ --silent -je {output} -etags {etags}"

	try:
		utilitat.execute(cmd,nucleiFolder / 'additional_checks','c2')
	except Exception as e:
		logger.error(e)

	print ('        - CVEs')
	output = nucleiFolder / 'additional_checks' / 'cves.json'
	cmd = f"{homePath}/{config['Binary']} -l {hosts_up} -t network/cves/ --silent -je {output} -etags {etags}"

	try:
		utilitat.execute(cmd,nucleiFolder / 'additional_checks','cves')
	except Exception as e:
		logger.error(e)

	print ('        - Exposures')
	output = nucleiFolder / 'additional_checks' / 'exposures.json'
	cmd = f"{homePath}/{config['Binary']} -l {hosts_up} -t network/exposures/ --silent -je {output} -etags {etags}"

	try:
		utilitat.execute(cmd,nucleiFolder / 'additional_checks','exposures')
	except Exception as e:
		logger.error(e)