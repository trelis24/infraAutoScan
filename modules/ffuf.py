import logging, os, re
import modules.utilitat as utilitat
from collections import defaultdict

logger = logging.getLogger(__name__)

def run(globalConf,scansDir,resultsDir):
	logger.info('Run')

	config = utilitat.load_config('config/ffuf.yaml')
	ffufDir = utilitat.new_folder(scansDir,config['FolderName'])
	ffufResultsDir = utilitat.new_folder(resultsDir,config['FolderName'])

	auth = utilitat.checkAuth(globalConf)
	print ('\n[*] Ffuf (noAuth)')
	wordlists = utilitat.get_wordlists(config,ffufDir)
	scope = get_scope(resultsDir)
	ffuf(scope,ffufDir,config,wordlists,'')
	if auth:
		print ('\n[*] Ffuf (Auth)')
		ffuf(scope,ffufDir,config,wordlists,auth)

	parse_results(ffufDir,ffufResultsDir)

# get scope from websites results folder. Get 200.
def get_scope(resultsDir):
	folder = os.path.join(resultsDir,'websites')
	file = os.path.join(folder,'200.txt')
	data = utilitat.read_file(file)
	return data

def parse_results(ffufDir,ffufResultsDir):
	logger.info('Parse result')
	print ('    - Parse results')

	for f in os.listdir(ffufDir):
		folder = os.path.join(ffufDir,f)
		if f != 'wordlists':
			# Read files
			results = {}
			results['Auth'] = {}
			results['noAuth'] = {}
			for filename in os.listdir(folder):
				file = os.path.join(folder,filename)
				if filename.endswith('.json') and 'test' not in filename and 'results' not in filename:
					if 'auth' in filename:
						auth = 'Auth'
					else:
						auth = 'noAuth'
					data = utilitat.read_json(file)
					for result in data['results']:
						status = str(result['status'])
						url = result['url']
						if status not in results[auth].keys(): # create key if first time
							results[auth][status] = []
						if url not in results[auth][status]: # remove duplicates
							results[auth][status].append(url)
						#print ('status: {},url: {}'.format(status,url))
			
			# Write results
			## JSON
			outFolder = utilitat.new_folder(ffufResultsDir,folder)
			utilitat.write_json(results,outFolder,'results.json')



			## By status
			for auth in ['Auth','noAuth']:
				o = utilitat.new_folder(ffufResultsDir,f)
				output = utilitat.new_folder(o,auth)
				for status in results[auth].keys():
					data = ''
					first = True
					for url in results[auth][status]:
						if first:
							data += url
							first = False
						else:
							data += '\n{}'.format(url)
					filename = '{}_{}.txt'.format(auth,status)
					utilitat.write_file(data,output,filename)


			## All
			for auth in ['Auth','noAuth']:
				o = utilitat.new_folder(ffufResultsDir,f)
				output = utilitat.new_folder(o,auth)
				data = ''
				first = True
				for status in results[auth].keys():
					for url in results[auth][status]:
						if first:
							data += url
							first = False
						else:
							data += '\n{}'.format(url)
				filename = '{}_all.txt'.format(auth)
				utilitat.write_file(data,output,filename)

def get_filters(config,ffufDir,outDir,headers,cookie,scope):
	logger.info('Define filters')

	wordlistsDir = utilitat.new_folder(ffufDir,'wordlists')

	# Create test wordlits
	words = ''
	first = True
	for word in config['WordlistTest']:
		if first:
			words += word
			first = False
		else:
			words += '\n{}'.format(word)
	test_wordlist = utilitat.write_file(words,wordlistsDir,'test.txt')

	# Execute ffuf
	outputDir = os.path.join(outDir,'test.json')
	target = '{}FUZZ'.format(scope)
	cmd = '{} -w {} -mc all {} {} -o {} -u {}'.format(config['Binary'],test_wordlist,headers,cookie,outputDir,target)
	try:
		result = utilitat.execute(cmd,outDir,'test')
		pass
	except Exception as e:
		logger.error(e)

	# Analyse 1
	json = utilitat.read_json(outputDir)
	status = json['results'][0]['status']
	f = ''
	if str(status) == '403' or str(status) == '404':
		f = '-fc {}'.format(status)
	elif str(status) == '200' or str(status) == '301':
		f = '-fw {}'.format(json['results'][0]['words'])
	
	# Execute 2
	outputDir2 = os.path.join(outDir,'test2.json')
	cmd = '{} -w {} -mc all {} {} -o {} -u {} {}'.format(config['Binary'],test_wordlist,headers,cookie,outputDir2,target, f)
	try:
		result = utilitat.execute(cmd,outDir,'test2')
	except Exception as e:
		logger.error(e)

	# Analyse 2
	json = utilitat.read_json(outputDir2)
	if not json['results']:
		logger.info('    - Filter automatically defined: {}'.format(f))
		return f

	# Could not be automatically defined
	prompt = '[i] Filter could not be automatically defined. Set one manually: '
	f = input(prompt)
	logger.info('    - Filter manually defined: {}'.format(f))
	return f




def get_target(depth,scope,ffufDir,exclusions):
	targets = []
	if depth == 0: # first iteration
		target = '{}FUZZ'.format(scope)
		return [target]

	last_depth = depth - 1
	for filename in os.listdir(ffufDir):
		if filename.endswith('.json') and 'directories' in filename and str(last_depth) in filename:
			json = os.path.join(ffufDir,filename)
			data = utilitat.read_json(json)
			for result in data['results']:
				fuzz = result['input']['FUZZ']
				status = result['status']
				redirection = result['redirectlocation']
				if fuzz not in exclusions:
					if redirection: # Get redirections (301, 302...)
						target = '{}FUZZ'.format(redirection)
						if target not in targets:
							targets.append(target)
						#print ('fuzz: {}, status: {}, redirection: {}'.format(fuzz,status,redirection))
	return targets

def get_target_name(target,scope):
	t = target.split(scope)[-1].split('FUZZ')[0]
	if not t:
		return 'root'
	else:
		return t[0:-1].replace('/','_')

def hostname2folderName(hostname):
	ip = hostname.replace('https://','https_')
	ip = ip.replace('http://','http_')
	ip = ip.replace('/','')
	ip = ip.replace(':','_')
	return ip

def ffuf(scopes,ffufDir,config,wordlists,auth):
	if auth:
		logger.info('Run Auth')
	else:
		logger.info('Run noAuth')

	# UserAgent
	headers = ''
	if config['UserAgent']:
		useragent = '"User-Agent: {}"'.format(config['UserAgent'])
		headers = '-H {}'.format(useragent)

	# Auth
	cookie = ''
	if auth:
		c = '"{}"'.format(auth)
		cookie = '-b {}'.format(c)

	# Flags
	flags = utilitat.get_flags(config['Flags'])

	for scope in scopes:
		print ('    - Running {}'.format(scope))
		fName = hostname2folderName(scope)

		outDir = utilitat.new_folder(ffufDir,fName)
		# Filters
		if config['Filter']:
			filters = config['Filter']
		else:
			filters = get_filters(config,ffufDir,outDir,headers,cookie,scope)

		# Run
		d = 0
		while d <= config['Depth']:
			targets = get_target(d,scope,outDir,config['WordlistsExclusion'])
			for target in targets:
				t = get_target_name(target,scope)
				for wordlist in wordlists:
					filename = wordlist.split('/')[-1].split('.')[0]
					terminal = 'Depth:{},Dict:{},Target:{}'.format(d,filename,t)
					if auth:
						name = 'auth_{}_{}_{}'.format(d,t,filename)
					else:
						name = '{}_{}_{}'.format(d,t,filename)
					output = '{}.json'.format(name)
					outputDir = os.path.join(outDir,output)
					cmd = '{} -w {} {} {} {} {} -o {} -u {}'.format(config['Binary'],wordlist,flags,headers,cookie,filters,outputDir,target)
					try:
						logger.info('    - {}'.format(terminal))
						result = utilitat.execute(cmd,outDir,name)	
					except Exception as e:
						logger.error(e)
			d = d + 1
	
		

	