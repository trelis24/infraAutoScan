import yaml, logging, os, shlex, subprocess, json, hashlib, base64, urllib.parse, unidecode, shutil
from pathlib import Path
from os import listdir
from os.path import isfile, join
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def is_sudo():
	if os.geteuid() != 0:
		return 0
	else:
		return 1

def get_listdir(path,ext):
	onlyfiles = [f for f in listdir(path) if isfile(join(path, f))]
	if ext:
		r = []
		for f in onlyfiles:
			if ext in f:
				r.append(f)
		return r
	else:
		return onlyfiles

def get_scope():
	globalConf = load_config('config/global.yaml')
	return globalConf['Scope']


def execute(cmd,path,name):
	if path == "DEVNULL":
		stdout = subprocess.PIPE
		stderr = subprocess.DEVNULL
	else:
		stdout = '{}/{}_stdout.txt'.format(path,name)
		stderr = '{}/{}_stderr.txt'.format(path,name)
		stdout = open(stdout, 'w')
		stderr = open(stderr, 'w')
	r = ''
	try:
		logger.debug('Executing {}'.format(cmd))
		r = subprocess.run(shlex.split(cmd),stdout=stdout,stderr=stderr)
	except Exception as e:
		logger.error('Execute: {}'.format(e))
	if path != 'DEVNULL':
		stdout.close()
		stderr.close()
	return r.stdout

def load_config(file):
	logger.info('Loading {}'.format(file))
	try:
		config = ''
		with open(file, 'r') as ymlfile:
			config = yaml.load(ymlfile, Loader=yaml.FullLoader)
	except Exception as e:
		logger.error('Error opening {}: {}'.format(file, e))

	return config

def new_folder(path,name):
	full_path = os.path.join(path,name)
	logger.info('New folder {}'.format(full_path))
	Path(full_path).mkdir(parents=True, exist_ok=True)
	return full_path


def get_flags(flags):
	results = ''
	for flag in flags:
		f = list(flag.keys())[0]
		if flag[f]:
			results += '{} '.format(f)
	return results

def read_json(input_file):
	with open(input_file, encoding='utf-8-sig') as json_file:
		text = json_file.read()
		json_data = json.loads(text)
	return json_data

def read_xml(input_file):
	with open(input_file, 'r') as f:
		soup = BeautifulSoup(f,  features="xml")
	return soup

def read_file(input_file):
	with open(input_file, 'r') as f:
		data = f.read().splitlines() 
	return data

def write_json(data, output_dir, output_filename):
	file = os.path.join(output_dir,output_filename)
	with open(file, 'w') as f:
		json.dump(data, f, indent=4)

def write_file(data, output_dir, output_filename):
	file = os.path.join(output_dir,output_filename)
	with open(file, 'w') as f:
		f.write(data)
	return file

def append_file(data, output_dir, output_filename):
	file = os.path.join(output_dir,output_filename)
	with open(file, 'a') as f:
		f.write(data)
	return file

def remove_duplicates(output_dir,output_filename):
	file = os.path.join(output_dir,output_filename)
	data = read_file(file)
	r = []
	for d in data:
		if d not in r:
			r.append(d)
	data = '\n'.join([str(elem) for elem in r])
	write_file(data, output_dir, output_filename)

# This functionality does not check if cookie or token are empty because it is checked by webAutoScan.py
def checkAuth(config):
	logger.info('Check authentication')
	if config['ScanType']['Auth']:
		if config['Authentication']['Token']:
			return config['Authentication']['Token']
		elif config['Authentication']['Cookie']:
			return config['Authentication']['Cookie']
	return 0

def remove_blank_lines(file):
	f = open(file,'r')
	lines = f.readlines()
	f.close()
	f = open(file,'w')
	for line in lines:
		if  line != '\n':
			f.write(line)
	f.close()

def load_wordlists(wordlistsFolder,magicString,exploitType):
	logger.info('Load wordlists')
	wordlists = ['',magicString]
	filename = '{}.txt'.format(exploitType)
	file = os.path.join(wordlistsFolder,filename)
	with open(file, 'r') as f:
		wordlists += f.read().splitlines()
	return wordlists

def load_requests(reqFolder):
	logger.info('Load requests')
	requests = {}
	for filename in os.listdir(reqFolder):
		req = {
		'file':filename,
		'method':'',
		'url':'',
		'headers': {},
		'params':''
		}
		file = os.path.join(reqFolder,filename)
		with open(file, 'r') as f:
			data = f.readlines()
			i = 0
			params = False # Allow post params detection after newline
			for line in data:
				line = line.strip()
				if i == 0:
					req['method'] = line.split(' ')[0]
					uri = line.split(' ')[1]
					if '?' in uri:
						req['params'] = uri.split('?')[1]
						uri = uri.split('?')[0]
				elif 'Host' in line:
					host = line.split(' ')[1]
					req['url'] = 'http://{}{}'.format(host,uri)
				else:
					if line != '':
						if not params:
							header_title = line.split(': ')[0]
							header_data = line.split(': ')[1]
							req['headers'][header_title] = header_data
						else:
							req['params'] = line
					else:
						params = True
				i = i + 1
		requests[filename] = req
	return requests
				
def get_hash(text):
	m = hashlib.sha256()
	m.update(str.encode(text))
	return m.hexdigest()

def encode_base64(text):
	s = str.encode(text)
	return base64.b64encode(s).decode('utf-8') 

def decode_base64(text):
	s = base64.b64decode(text).decode('utf-8') 
	return s

def url_encode(s):
	encoded = urllib.parse.quote(s)
	encoded = encoded.replace('%3D','=')
	encoded = encoded.replace('%26','&')
	return encoded

# Get the wordlists, join them and returns the path
def get_wordlists(config,output_dir):
	logger.info('Create wordlists')
	print('    - Create wordlists')

	wordlists = []
	WordlistsType = config['WordlistsType']
	wordlistsDir = new_folder(output_dir,'wordlists')
	for key in config['Wordlists'].keys():
		if config['Wordlists'][key]:
			w_name = 'Wordlists{}'.format(key)
			w = join_wordlists(config[w_name],WordlistsType)
			filename = '{}.txt'.format(key.lower())
			file = write_file(w,wordlistsDir,filename)
			wordlists.append(file)
	return wordlists

def join_wordlists(wordlists,WordlistsType):
	data = ''
	w_dirs = []
	if WordlistsType == 'ALL':
		for key in wordlists.keys():
			w_dirs += wordlists[key]
	else:
		w_dirs = wordlists[WordlistsType]
	for w in w_dirs:
		with open(w) as f:
			data += f.read()
		data += "\n"
	data_list = data.split('\n')
	sort = list(set(data_list))
	sort.remove('')
	data = '\n'.join(sort)
	return data

# Used in exploits to store the summary in different files
def store_exploit_summary(file,summary,exploitResultsDir,):
	logger.info('Save summary')

	filename = file.split('.')[0]
	reqDir = new_folder(exploitResultsDir,filename)
	for key in summary.keys():
		data = summary[key]
		
		if key == 'status':
			categoryDir = new_folder(reqDir,key)
			for code in data.keys():
				statusData = data[code]
				name = '{}.txt'.format(code)
				write_json(statusData,categoryDir,name)
		else:
			if data:
				name = '{}.txt'.format(key)
				write_json(data,reqDir,name)

def decode_unicode(data):
	data = unidecode.unidecode(data)
	data = data.strip()
	return data

def dict_filename(name):
	if name == 'microsoft-ds':
		return 'smb'
	if name == 'ms-wbt-server':
		return 'rdp'
	return name

def remove_directory(path):
	try:
		shutil.rmtree(path)
	except:
		pass

def remove_file(path):
	try:
		os.remove(path)
	except:
		pass

def hostname2ip(hostname):
	ip = hostname.replace('https://','')
	ip = ip.replace('http://','')
	ip = ip.replace('/','')
	return ip