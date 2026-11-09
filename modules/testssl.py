from openpyxl import load_workbook
from openpyxl.styles import PatternFill, Alignment
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import CellIsRule
import pandas as pd
import logging, os, re, json
import modules.utilitat as utilitat

logger = logging.getLogger(__name__)

def run(globalConf,scansDir,resultsDir):
	logger.info('Run')
	print ('\n[*] TestSSL')

	config = utilitat.load_config('config/testssl.yaml')
	testsslDir = utilitat.new_folder(scansDir,config['FolderName'])

	nmapConf = utilitat.load_config('config/nmap.yaml')
	resultsNmap = os.path.join(resultsDir,nmapConf['FolderName'])
	nmapFile = os.path.join(resultsNmap,'ssl_tls.txt')

	r = noAuth(testsslDir,config,nmapFile)
	if r:
		results, resultsTestSSL = parse_results(testsslDir,resultsDir)
		ssl_tls_annex(results, resultsTestSSL)

def parse_results(testsslDir,resultsDir):
	print ('    - Parse results')
	logger.info('    - Parse results')
	resultsTestSSL = utilitat.new_folder(resultsDir,'testssl')
	file = os.path.join(testsslDir,'testssl.json')
	json_data = utilitat.read_json(file)
	results = parse_json(json_data)
	store_results(results, resultsTestSSL)
	return results, resultsTestSSL

def parse_json(json_data):
	results = {
		'protocols': {
			'SSLv2': [],
			'SSLv3': [],
			'TLS1': [],
			'TLS1_1': [],
			'TLS1_2': [],
			'TLS1_3': []
		},
		'vulnerabilities': {
			'heartbleed': [],
			'CCS': [],
			'ticketbleed': [],
			'ROBOT': [],
			'secure_renego': [],
			'secure_client_renego': [],
			'CRIME_TLS': [],
			'BREACH': [],
			'POODLE_SSL': [],
			'fallback_SCSV': [],
			'SWEET32': [],
			'FREAK': [],
			'DROWN': [],
			'LOGJAM': [],
			'BEAST': [],
			'LUCKY13': [],
			'RC4': []
		},
		'ciphers': { #fs
			'CBC': [],
			'DES': [],
			'RC4': []
		},
		'certs': { #serverDefaults
			'cert_trust': [],
			'cert_chain_of_trust': [],
			'cert_expirationStatus': [],
			'cert_keySize': [],
			'cert_signatureAlgorithm': []
		},
		'error':[]
	}

	for target in json_data['scanResult']:
		if not 'ip' in target.keys():
			# Connection Errors
			pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})')
			try:
				ip = pattern.search(target['finding'])[0]
				results['error'].append(ip)
			except:
				pass
		else:
			# Protocols
			for protocol in target['protocols']:
				if protocol['id'] in results['protocols'].keys():
					# Vulns or TLS1.2 and TLS1.3
					if (protocol['severity'] != 'OK' and protocol['severity'] != 'INFO') or (protocol['severity'] == 'OK' and (protocol['finding'] == 'offered' or protocol['finding'] == 'offered with final')):
						server = '{}:{}'.format(target['ip'],target['port'])
						results['protocols'][protocol['id']].append(server)

			# Vulnerabilities
			try:
				if 'vulnerabilities' in target.keys():
					for vuln in target['vulnerabilities']:
						if vuln['id'] in results['vulnerabilities'].keys():
							if vuln['severity'] != 'OK' and vuln['severity'] != 'INFO':
								server = '{}:{}'.format(target['ip'],target['port'])
								results['vulnerabilities'][vuln['id']].append(server)
			except:
				pass
			# Ciphers
			try: 
				t = target['serverPreferences']
				for cipher in t:
					for key in results['ciphers'].keys():
						if key in cipher['finding'] and 'cipherorder' not in cipher['id']:
							c = list(filter(None, cipher['finding'].split(' ')))[2]
							if c not in results['ciphers'][key]:
								results['ciphers'][key].append(c)
			except:
				t = target['cipherTests']
				for cipher in t:
					for key in results['ciphers'].keys():
						if key in cipher['finding'] and 'cipherorder' not in cipher['id']:
							c = list(filter(None, cipher['finding'].split(' ')))[1]
							if c not in results['ciphers'][key]:
								results['ciphers'][key].append(c)

			# Certs
			try:
				if 'serverDefaults' in target.keys():
					for cert in target['serverDefaults']:
						if cert['id'] in results['certs'].keys():
							if (cert['severity'] != 'OK' and cert['severity'] != 'INFO'):
								server = '{}:{}'.format(target['ip'],target['port'])
								results['certs'][cert['id']].append(server)
			except:
				pass

	return results

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

def noAuth(testsslDir,config,nmapDir):
	logger.info('Run noAuth')
	print ('    - Run')
	
	flags = utilitat.get_flags(config['Flags'])

	if config['Source']['Nmap']:
		input_file = nmapDir
		filename = 'testssl'
	elif config['Source']['Manual']:
		if config['Manual'][0]:
			print (config['Manual']) # TODO
		else:
			print ('    [!] Manual scope empty!')
			logger.warning('Manual scope empty!')
			return 0

	# Check if ssl_tls.txt is empty/does not exist
	if not os.path.isfile(input_file) or os.path.getsize(input_file) < 10:
		logger.warning('{} is empty or file does not exist!'.format(input_file))
		print ('    [!] No SSL/TLS hosts detected')
		return 0

	cmd = '{} {} -iL {} -oA {}/{}'.format(config['Binary'],flags,input_file,testsslDir,filename)

	try:
		utilitat.execute(cmd,testsslDir,filename)
		return 1
	except Exception as e:
		logger.error(e)

	
def ssl_tls_annex(results, resultsDir):
	# === Extract only the sections we care about ===
	results_parsed = {
		"protocols": results.get("protocols", {}),
		"vulnerabilities": results.get("vulnerabilities", {})
	}

	# === Remove TLS1_2 and TLS1_3 from protocols ===
	for unwanted_key in ["TLS1_2", "TLS1_3"]:
		results_parsed["protocols"].pop(unwanted_key, None)

	# === Collect all unique IPs ===
	all_ips = set()
	for category in results_parsed.values():
		for lst in category.values():
			all_ips.update(lst)

	# === Create DataFrame ===
	df = pd.DataFrame(index=sorted(all_ips))

	# === Populate columns with X where applicable ===
	for category_name, category_data in results_parsed.items():
		for name, ips in category_data.items():
			df[name] = df.index.map(lambda ip: 'X' if ip in ips else '')

	# === Save to Excel and CSV ===
	file_to_csv = os.path.join(resultsDir,'SSL_TLS_Annex.csv')
	df.to_csv(file_to_csv)
	excel_filename = os.path.join(resultsDir,'SSL_TLS_Annex.xlsx')
	df.to_excel(excel_filename)


	# === Open with openpyxl to add formatting ===
	wb = load_workbook(excel_filename)
	ws = wb.active

	# === Define red fill for cells with "X" ===
	red_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")

	# === Apply conditional formatting to all data cells ===
	# Determine data range (excluding header)
	data_range = f"B2:{get_column_letter(ws.max_column)}{ws.max_row}"
	ws.conditional_formatting.add(data_range, CellIsRule(operator='equal', formula=['"X"'], fill=red_fill))

	# === Center all data cells ===
	for row in ws.iter_rows(min_row=2, min_col=2, max_row=ws.max_row, max_col=ws.max_column):
		for cell in row:
			cell.alignment = Alignment(horizontal='center', vertical='center')

	# === Auto-adjust column widths ===
	for column_cells in ws.columns:
		max_length = 0
		column = column_cells[0].column_letter
		for cell in column_cells:
			if cell.value:
				max_length = max(max_length, len(str(cell.value)))
		adjusted_width = (max_length + 2)
		ws.column_dimensions[column].width = adjusted_width

	# === Save the formatted workbook ===
	wb.save(excel_filename)