import logging, os, requests, warnings
import modules.utilitat as utilitat
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from bs4 import MarkupResemblesLocatorWarning
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)

def run(globalConf,scansDir,resultsDir):
	logger.info('Run')

	config = utilitat.load_config('config/checkHTTPFfuf.yaml')
	checkHTTPDir = utilitat.new_folder(scansDir,config['WebsitesFolderName'])
	checkHTTPResultsDir = utilitat.new_folder(resultsDir,config['FolderName'])

	print ('\n[*] Check websites')

	get_scope(checkHTTPDir,resultsDir)
	check_availability(checkHTTPDir,config['UserAgent'])
	parse_results(checkHTTPDir,checkHTTPResultsDir)

def parse_results(checkHTTPDir,checkHTTPResultsDir):
	print ('    - Parse results')

	# Errors
	file = os.path.join(checkHTTPDir,'errors_all.json')
	json = utilitat.read_json(file)
	data = ''
	first = True
	for key in json.keys():
		if first:
			data = key
			first = False
		else:
			data = '{}\n\n{}'.format(data,key)
		for ip in json[key]:
			data = '{}\n{}'.format(data,ip)
	utilitat.write_file(data,checkHTTPResultsDir,'errors_all.txt')

	# byStatus
	file = os.path.join(checkHTTPDir,'results_all.json')
	json = utilitat.read_json(file)
	status = {}
	for ip in json.keys():
		code = json[ip]['status']
		if code not in status:
			status[code] = []
		status[code].append(ip)
	for code in status.keys():
		data = ''
		first = True
		for ip in status[code]:
			if first:
				data = ip
				first = False
			else:
				data = '{}\n{}'.format(data,ip)
		filename = '{}_all.txt'.format(code)
		utilitat.write_file(data,checkHTTPResultsDir,filename)

	# byTitle
	file = os.path.join(checkHTTPDir,'results_all.json')
	json = utilitat.read_json(file)
	title = {}
	for ip in json.keys():
		t = json[ip]['title']
		if not t:
			t = 'No title in this website'
		if t not in title:
			title[t] = []
		title[t].append(ip)
	data = ''
	first = True
	for t in title.keys():
		if first:
			data = t
			first = False
		else:
			data = '{}\n\n{}'.format(data,t)
		for ip in title[t]:
			data = '{}\n{}'.format(data,ip)
	utilitat.write_file(data,checkHTTPResultsDir,'titles_all.txt')

def check_availability(checkHTTPDir,UserAgent):
	print ('    - Check websites')
	file = os.path.join(checkHTTPDir,'urls_all.txt')
	urls = utilitat.read_file(file)
	results = {}
	errors = {}
	for url in urls:
		headers = {"User-Agent":UserAgent}
		try:
			response = requests.get(url,verify=False,timeout=10,headers=headers)
		except Exception as e:
			t = type(e).__name__
			if t in errors.keys():
				errors[t].append(url)
			else:
				errors[t] = [url]
		else:
			status = response.status_code
			html = BeautifulSoup(response.text,features="lxml")
			try:
				title = utilitat.decode_unicode(html.title.text)
			except:
				title = ''
			if response.history:
				redirecton = response.url
			else:
				redirecton = ''
			results[url] = {'status':status,'title':title,'redirection':redirecton}
	
	utilitat.write_json(results,checkHTTPDir,'results_all.json')
	utilitat.write_json(errors,checkHTTPDir,'errors_all.json')

def get_scope(checkHTTPDir,resultsDir):
	print ('    - Get scope')
	f = os.path.join(resultsDir,'ffuf')
	folders = os.listdir(f)

	urls = []
	for folder in folders:
		path = os.path.join(f,folder)
		path = os.path.join(path,'noAuth')
		files = utilitat.get_listdir(path,'.txt')
		for file in files:
			if 'all' in file:
				r_file = os.path.join(path,file)
				urls += utilitat.read_file(r_file)
				break

	data = ''
	first = True
	for url in urls:
		if first:
			data = url
			first = False
		else:
			data = '{}\n{}'.format(data,url)
	utilitat.write_file(data,checkHTTPDir,'urls_all.txt')