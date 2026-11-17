import logging, os, re, json
from pathlib import Path



print('Run Nuclei')
config = {}
nmapFolder = Path('C:\\Users\\AlbertTrelis\\OneDrive - Eurofins ITWW\\Auditories\\In Progress\\bp-jp\\bpjp_infra\\bpjp_top1000_hosts\\results\\nmap\\advanced_byService')
config['NucleiTemplates'] = Path('../nuclei-templates')
config['binary'] = '~/go/bin/nuclei'

# Check workflows
workflows = []
for entry in nmapFolder.iterdir():
	tech = entry.stem if entry.is_file() else entry.name  
	print (f'Tech: {tech}')
	workflow_path = config['NucleiTemplates'] / 'workflows' / f'{tech}-workflow.yaml'
	if (workflow_path).is_file():
		workflow = {
			'tech':tech,
			'yaml':f'{tech}-workflow.yaml',
			'json':f'{tech}-workflow.json'
		}
		workflows.append(workflow)
		print (f'Workflow: {workflow}')

nucleiFolder = Path('scans\\nuclei\\')
for workflow in workflows:
	output = nucleiFolder / workflow['tech'] / workflow['json']
	nmap_ips = nmapFolder / workflow['tech'] / 'ip.txt'
	cmd = f'{config['binary']} -l results/nmap/advanced_byService/ftp/ip.txt -w workflows/{workflow['yaml']} --silent -je {output}'
	print (cmd)

