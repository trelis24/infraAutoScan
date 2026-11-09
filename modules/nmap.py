import logging, os, re
import modules.utilitat as utilitat

logger = logging.getLogger(__name__)

def run(globalConf,scansDir,resultsDir):
	logger.info('Run')
	

	config = utilitat.load_config('config/nmap.yaml')
	nmapDir = utilitat.new_folder(scansDir,config['FolderName'])
	resultsNmap = utilitat.new_folder(resultsDir,'nmap')
	blacklist = utilitat.read_file('config/nmap_blacklist.txt')

	scope = utilitat.get_scope()
	nmap(scope,nmapDir,config)
	parse(nmapDir,resultsNmap,config)
	advanced(nmapDir,resultsNmap,config)
	parse_advanced(nmapDir,resultsNmap,resultsDir,blacklist)
	parse_extra(nmapDir,resultsNmap)

def add(vulns,script_name,output,ip,port):
	hash_value = utilitat.get_hash(output)
	host = '{}:{}'.format(ip,port)
	# key exists
	if script_name in vulns:
		new = True
		for script in vulns[script_name]:
			if script['hash'] == hash_value:
				new = False
				if not host in script['ip']:

					script['ip'].append(host)
		if new:

			d = {'ip': [host], 'output': output, 'hash': hash_value}
			vulns[script_name].append(d) 
	else:
		d = {'ip': [host], 'output': output, 'hash': hash_value}
		vulns[script_name] = [d] 

def parse_byIp(nmapDir,scansDir,resultsNmap):
	# Advanced by Port
	scans_byPort = os.path.join(nmapDir,'advanced_byPort')
	results_byPort = os.path.join(resultsNmap,'advanced_byPort')
	files = utilitat.get_listdir(scans_byPort,'.json')
	for f in files:
		# Get IPs
		ips_byPort = []
		file = os.path.join(scans_byPort,f)
		data = utilitat.read_json(file)
		for key in data.keys():
			for elem in data[key]:
				ips_byPort += elem['ip']

		# save results
		ips_byPort = list(dict.fromkeys(ips_byPort)) # remove duplicates
		folder = f.replace('.json','')
		output = os.path.join(results_byPort,folder)
		data_ip = ''
		first = True
		for ip in ips_byPort:
			if first:
				data_ip = '{}'.format(ip)
				first = False
			else:
				data_ip = '{}\n{}'.format(data_ip,ip)

		utilitat.write_file(data_ip,output,'ip.txt')

	# Advanced by Servcie
	scans_byService = os.path.join(nmapDir,'advanced_byService')
	results_byService = os.path.join(resultsNmap,'advanced_byService')
	files = utilitat.get_listdir(scans_byService,'.json')
	for f in files:
		# Get IPs
		ips_byService = []
		file = os.path.join(scans_byService,f)
		data = utilitat.read_json(file)
		for key in data.keys():
			for elem in data[key]:
				ips_byService += elem['ip']

		# save results
		ips_byService = list(dict.fromkeys(ips_byService)) # remove duplicates
		folder = f.replace('.json','')
		output = os.path.join(results_byService,folder)
		data_ip = ''
		first = True
		for ip in ips_byService:
			if first:
				data_ip = '{}'.format(ip)
				first = False
			else:
				data_ip = '{}\n{}'.format(data_ip,ip)

		utilitat.write_file(data_ip,output,'ip.txt')

def parse_byUrl(nmapDir,scansDir,resultsDir):
	scans_byPort = os.path.join(nmapDir,'advanced_byPort')
	results_byPort = os.path.join(resultsDir,'advanced_byPort')
	files = utilitat.get_listdir(scans_byPort,'.json')
	url_http = []
	for f in files:
		# Get IPs
		file = os.path.join(scans_byPort,f)
		data = utilitat.read_json(file)
		try:
			for elem in data['service']:
				if 'http' in elem['output']:
					url_http += elem['ip']
		except:
			pass

	# save results
	url_http = list(dict.fromkeys(url_http)) # remove duplicates
	data_ip = ''
	first = True
	for ip in url_http:
		if first:
			data_ip = '{}'.format(ip)
			first = False
		else:
			data_ip = '{}\n{}'.format(data_ip,ip)

	utilitat.write_file(data_ip,resultsDir,'http.txt')


def parse_byPort(nmapDir,scansDir,resultsNmap,blacklist):
	# Parse by ports
	files = utilitat.get_listdir(scansDir,'.xml')
	for f in files:
		file = os.path.join(scansDir,f)

		soup = utilitat.read_xml(file)
		vulns = {}
		service = ''
		port_num = ''
		for host in soup.find_all('host'):
			ip = host.find('address')['addr']
			port = host.find('port')
			port_num = port['portid']
			try:
				service = port.find('service')['name']
				service = utilitat.dict_filename(service)
			except:
				break
			else:
				add (vulns,'service',service,ip,port_num)
			try:
				version = '{} {}'.format(port.find('service')['product'],port.find('service')['version'])
			except:
				pass
			else:
				add (vulns,'version',version,ip,port_num)
				
			
			for script in host.find_all('script'):
				script_name = script['id']
				output = script['output']
				output = utilitat.decode_unicode(output)
				add (vulns,script_name,output,ip,port_num)

		# save json
		jsonDir = utilitat.new_folder(nmapDir,'advanced_byPort')
		jsonFile = f.replace('.xml','.json')
		utilitat.write_json(vulns, jsonDir, jsonFile)

		# save results
		resultsAdvanced = utilitat.new_folder(resultsNmap,'advanced_byPort')
		folder = f.replace('.xml','')
		output = utilitat.new_folder(resultsAdvanced,folder)
		for key in vulns.keys():
			output_file = '{}/{}.txt'.format(output,key)
			written = False
			with open(output_file, 'w') as f:
				for vuln in vulns[key]:
					first = True
					for ip in vuln['ip']:
						if vuln['hash'] not in blacklist:
							if first:
								s = '{}\n{}'.format(vuln['output'],ip) 
								first = False
							else:
								s = '\n{}'.format(ip)
							f.write(s)
							written = True
					#s = '\n{}\n\n'.format(vuln['output'])
					s = '\n' 
					f.write(s)
			if not written:
				os.remove(output_file)
		


def merge (json1, json2):
	for key in json1.keys():
		if key in json2.keys(): # key exists, merge
			for elem1 in json1[key]:
				h1 = elem1['hash']
				found = False
				for elem2 in json2[key]:
					h2 = elem2['hash']
					if h1 == h2: # same hash, just add ips
						elem2['ip'] += elem1['ip']
						found = True
						break
				if not found: # if key exists, but not hash found, append
					json2[key].append(elem1)
		else: # key do not exists, just add
			json2[key] = json1[key]
	return json2

# If service does not exist, copy json. If exists, merge.
def parse_byService(nmapDir,scansDir,resultsNmap,blacklist):
	advanced_byPort = os.path.join(nmapDir,'advanced_byPort')
	files = utilitat.get_listdir(advanced_byPort,'.json')

	# remove directory to avoid duplicates if multiple executions
	advanced_byService = os.path.join(nmapDir,'advanced_byService')
	utilitat.remove_directory(advanced_byService)
	
	advanced_byService = utilitat.new_folder(nmapDir,'advanced_byService')

	for f in files: # Get first file
		file = os.path.join(advanced_byPort,f)
		json = utilitat.read_json(file)
		try:
			service = json['service'][0]['output']
		except:
			pass
		else:
			json_services = utilitat.get_listdir(advanced_byService,'.json')
			service_file = '{}.json'.format(service)
			if service_file not in json_services: # if it does not exist, copy json
				utilitat.write_json(json,advanced_byService,service_file)
			else: # if exist, merge
				file2 = os.path.join(advanced_byService,service_file)
				json2 = utilitat.read_json(file2)
				result = merge(json,json2)
				utilitat.write_json(result,advanced_byService,service_file)

	# save results
	files = utilitat.get_listdir(advanced_byService,'.json')
	for f in files:
		file = os.path.join(advanced_byService,f)
		resultsAdvanced = utilitat.new_folder(resultsNmap,'advanced_byService')
		folder = f.replace('.json','')
		output = utilitat.new_folder(resultsAdvanced,folder)
		vulns = utilitat.read_json(file)
		for key in vulns.keys():
			output_file = '{}/{}.txt'.format(output,key)
			written = False
			with open(output_file, 'w') as f:
				for vuln in vulns[key]:
					first = True
					for ip in vuln['ip']:
						if vuln['hash'] not in blacklist:
							if first:
								s = '{}'.format(ip)
								first = False
							else:
								s = '\n{}'.format(ip)
							f.write(s)
							written = True
					s = '\n{}\n\n'.format(vuln['output'])
					f.write(s)
			if not written:
				os.remove(output_file)

def parse_advanced(nmapDir,resultsNmap,resultsDir,blacklist):
	print ('    - Parse advanced')
	scansDir = utilitat.new_folder(nmapDir,'advanced')

	parse_byPort(nmapDir,scansDir,resultsNmap,blacklist)
	parse_byService(nmapDir,scansDir,resultsNmap,blacklist)
	parse_byIp(nmapDir,scansDir,resultsNmap)
	parse_byUrl(nmapDir,scansDir,resultsDir)

def advanced(nmapDir,resultsNmap,config):
	print ('\n[*] Nmap Advanced')
	
	script = get_script(config['Advanced'])
	outDir = utilitat.new_folder(nmapDir,'advanced')

	portFolder = os.path.join(resultsNmap,'ports')
	files = utilitat.get_listdir(portFolder,'.txt')
	for f in files:
		outFile = f.replace('.txt','')
		print('    - {}'.format(outFile.replace('_',' ')))
		udp = ''
		if not config['Advanced']['Protocol']['TCP']:
			if 'tcp' in f:
				continue
		if not config['Advanced']['Protocol']['UDP']:
			if 'udp' in f:
				continue
		else:
			if 'udp' in f:
				udp = '-sU'

		file = os.path.join(portFolder,f)
		p = f.split('_')[0]
		if utilitat.is_sudo():
			cmd = '{} -sV --script "{}" -p {} -oA {}/{} -iL {} {}'.format(config['Binary'],script,p,outDir,outFile,file,udp)
		else:
			if udp:
				print ('    [!] No sudo rights. Skipping test.')
				logger.warning('No sudo rights. Skipping test.')
			cmd = '{} -sV --script "{}" -p {} -oA {}/{} -iL {}'.format(config['Binary'],script,p,outDir,outFile,file)
		try:
			logger.info('    - Advanced {}'.format(p))
			result = utilitat.execute(cmd,outDir,outFile)
		except Exception as e:
			logger.error(e)

def parse(nmapDir,resultsNmap,config):
	print ('    - Parse')
	files = utilitat.get_listdir(nmapDir,'.xml')
	
	portFolder = ''
	serviceFolder = ''
	productFolder = ''

	for f in files:
		file = os.path.join(nmapDir,f)
		xml = utilitat.read_xml(file)

		portFolder = utilitat.new_folder(resultsNmap,'ports')
		serviceFolder = utilitat.new_folder(resultsNmap,'services')
		productFolder = utilitat.new_folder(resultsNmap,'products')
		hosts = xml.find_all('host')
		for host in hosts:
			ip = host.find('address')['addr']
			ports = host.find_all('port')
			for port in ports:
				state = port.find('state')['state']
				if state == 'open':
					# By ports
					port_num = port['portid']
					protocol = port['protocol']
					filename = '{}_{}.txt'.format(port_num,protocol)
					data = '{}\n'.format(ip)
					utilitat.append_file(data,portFolder,filename)

					# By services
					try:
						service = port.find('service')['name']
					except:
						pass
					else:
						filename = '{}.txt'.format(service).replace(' ','').replace('/','')
						data = '{}:{}\n'.format(ip,port_num)
						utilitat.append_file(data,serviceFolder,filename)

					# By products
					try:
						product = port.find('service')['product']
					except:
						pass
					else:
						filename = '{}.txt'.format(product).replace(' ','').replace('/','')
						data = '{}:{}\n'.format(ip,port_num)
						utilitat.append_file(data,productFolder,filename)

	remove_duplicates(portFolder)
	remove_duplicates(serviceFolder)
	remove_duplicates(productFolder)


def remove_duplicates(folder):
	files = utilitat.get_listdir(folder,'.txt')
	for f in files:
		utilitat.remove_duplicates(folder,f)


def parse_extra(nmapDir,resultsNmap):
	logger.info('Parse result')
	print ('\n[*] Parse Nmap')
	advancedDir = os.path.join(nmapDir,'advanced_byService')
	

	parse_ssl(advancedDir,resultsNmap)
	parse_ssl_ciphers(advancedDir,resultsNmap,nmapDir)
	#vulnerabilities(bs_data,resultsNmap)


def vulnerabilities(bs_data,resultsNmap):
	tables = bs_data.find_all('table')
	file = os.path.join(resultsNmap,'vulnerabilities.txt')
	with open(file, 'a') as f:
		hostname = bs_data.find('hostname').get('name')
		port = bs_data.find('port').get('portid')
		data = '{}:{}\n'.format(hostname,port)
		f.write(data)
		for table in tables:
			elems = table.find_all('elem', key='state')
			for elem in elems:
				if elem.text == 'VULNERABLE':
					title = table.find('elem', key='title')
					data = '{}\n'.format(title.text)
					f.write(data)

		data = '\n'
		f.write(data)

def parse_ssl_ciphers(advancedDir,resultsNmap,nmapDir):
	print ('    - SSL/TLS Vulnerabilities')
	file = os.path.join(resultsNmap,'ssl_tls_ciphers.txt')
	utilitat.remove_file(file)
	results = {}
	for filename in os.listdir(advancedDir):
		file = os.path.join(advancedDir,filename)
		json = utilitat.read_json(file)
		if 'ssl-enum-ciphers' in json.keys():
			for elem in json['ssl-enum-ciphers']:
				if 'SSLv2.0' in elem['output']:
					if not 'DROWN' in results.keys():
						results['DROWN'] = elem['ip']
					else:
						results['DROWN'] += elem['ip']
				if 'SSLv3.0' in elem['output']:
					if not 'POODLE' in results.keys():
						results['POODLE'] = elem['ip']
					else:
						results['POODLE'] += elem['ip']
				if ('SSLv3.0' in elem['output'] or 'TLSv1.0' in elem['output']) and 'CBC' in elem['output']:
					if not 'BEAST' in results.keys():
						results['BEAST'] = elem['ip']
					else:
						results['BEAST'] += elem['ip']
				if 'CBC' in elem['output']:
					if not 'LUCKY13' in results.keys():
						results['LUCKY13'] = elem['ip']
					else:
						results['LUCKY13'] += elem['ip']
				if 'RC4' in elem['output']:
					if not 'RC4' in results.keys():
						results['RC4'] = elem['ip']
					else:
						results['RC4'] += elem['ip']
				if 'EXP' in elem['output']:
					if not 'LOGJAM' in results.keys():
						results['LOGJAM'] = elem['ip']
					else:
						results['LOGJAM'] += elem['ip']
				if 'DES' in elem['output']:
					if not 'SWEET32' in results.keys():
						results['SWEET32'] = elem['ip']
					else:
						results['SWEET32'] += elem['ip']

	# Remove duplicates
	for key in results.keys():
		elem = results[key]
		results[key] = list(dict.fromkeys(elem))

	# Write
	data = ''
	first = True
	for key in results.keys():
		elem = results[key]
		if first:
			data += key
			first = False
		else:
			data += '\n\n{}'.format(key)
		for ip in elem:
			data += '\n{}'.format(ip)
	utilitat.write_file(data,resultsNmap,'ssl_tls_ciphers.txt')

def parse_ssl(advancedDir,resultsNmap):
	print ('    - SSL/TLS Services')
	file = os.path.join(resultsNmap,'ssl_tls.txt')
	utilitat.remove_file(file)
	data = ''
	first = True
	for filename in os.listdir(advancedDir):
		file = os.path.join(advancedDir,filename)
		json = utilitat.read_json(file)
		if 'ssl-enum-ciphers' in json.keys():
			for elem in json['ssl-enum-ciphers']:
				for ip in elem['ip']:
					if first:
						data += ip
						first = False
					else:
						data += '\n{}'.format(ip)				
	utilitat.write_file(data,resultsNmap,'ssl_tls.txt')


def get_script(advanced):
	script = ''
	#Include
	first = True
	for include in advanced['Include']:
		if first:
			script += '({}'.format(include)
			first = False
		else:
			script += ' or {}'.format(include)
	script += ')'

	#Exclude
	first = True
	i = 10 # need to add () or () every some scripts, otherwise nmap breaks
	for exclude in advanced['Exclude']:
		if first:
			script += ' and not (({}'.format(exclude)
			first = False
		else:
			script += ' or {}'.format(exclude)
			i = i - 1
			if i == 0:
				script += ') or ({}'.format(exclude)
				i = 10
	script += '))'
	return script

def nmap(scope,nmapDir,config):
	logger.info('Run nmap')
	ports = config['Ports']

	# TCP
	if config['Protocol']['TCP']:
		for port in ports:
			ports_flag = list(port.keys())[0]
			if port[ports_flag]:
				print ('\n[*] Nmap {}'.format(ports_flag))
				p = ''
				if ports_flag == 'Fast':
					p = '-F'
				elif ports_flag == 'Full':
					p = '-p-'
				elif ports_flag == 'Advanced':
					break
				
				flags = utilitat.get_flags(config['Flags'])
				if utilitat.is_sudo():
					cmd = '{} {} {} -oA {}/{} -iL {}'.format(config['Binary'],p,flags,nmapDir,ports_flag,scope)
				else:
					cmd = '{} {} {} -oA {}/{} -iL {}'.format(config['Binary'],p,flags,nmapDir,ports_flag,scope)
				try:
					print ('    - {}'.format(ports_flag))
					logger.info('    - {}'.format(ports_flag))
					result = utilitat.execute(cmd,nmapDir,ports_flag)
				except Exception as e:
					logger.error(e)
		

	# UDP
	if config['Protocol']['UDP']:
		print ('\n[*] Nmap UDP')
		logger.info('    - UDP')
		flags = utilitat.get_flags(config['Flags'])
		if utilitat.is_sudo():
			cmd = '{} -sU -sV -p 53,67,68,69,88,111,123,135,137,138,161,162,177,389,500,514,520,623,631,1434,1900,3389,4500,5353,5060 {} --max-retries 1 -oA {}/udp -iL {}'.format(config['Binary'],flags,nmapDir,scope)
			try:
				result = utilitat.execute(cmd,nmapDir,'udp')
			except Exception as e:
				logger.error(e)
		else:
			print ('    [!] No sudo rights. Skipping test.')
			logger.warning('No sudo rights. Skipping test.')

	