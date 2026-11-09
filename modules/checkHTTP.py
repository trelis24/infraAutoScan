import logging, os, requests, warnings, urllib3, re
from urllib.parse import urljoin
import modules.utilitat as utilitat
from bs4 import BeautifulSoup,Comment
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from bs4 import MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
from collections import defaultdict


logger = logging.getLogger(__name__)

def run(globalConf,scansDir,resultsDir):
	logger.info('Run')

	config = utilitat.load_config('config/checkHTTP.yaml')
	checkHTTPDir = utilitat.new_folder(scansDir,config['FolderName'])
	checkHTTPResultsDir = utilitat.new_folder(resultsDir,config['FolderName'])

	print ('\n[*] Check websites')

	get_scope(checkHTTPDir,resultsDir)
	check_availability(checkHTTPDir,config['UserAgent'])
	parse_results(checkHTTPDir,checkHTTPResultsDir)

def check_login2(response):
	LOGIN_KEYWORDS = ['login','log in', 'sign in', 'username', 'password', 'passwd', 'authenticate', 'admin', 'portal']
	if response.status_code == 401 and response.headers.get('WWW-Authenticate',''):
		return True,'BasicAuth'
	html = BeautifulSoup(response.text,features="lxml")

	# Password field
	for i in html.find_all('input'):
		if i.get('type','').lower() == 'password':
			return True,'Input'

	# Title keyboard
	title = html.find('title')
	if title and any(kw in title.text.lower() for kw in LOGIN_KEYWORDS):
		return True,'Title'

	# Form action
	for f in html.find_all('form'):
		if any(kw in f.get('action','').lower() for kw in LOGIN_KEYWORDS):
			return True,'Form'

	return False,''

def check_login_paths(ip):
	LOGIN_PATHS = ['/login','admin','admin/login','wp-login.php','/user/login','/signin','/auth','/panel','/management','/console','/portal','/rui/','cgi-bin/login.cgi']
	# Common paths
	for path in LOGIN_PATHS:
		try:
			r = session.get(ip + path, timeout=10, allow_redirects=False, verify=False)
			if r.status_code in [200,401,403]:
				return check_login(r),'Path'
		except:
			pass
	return False,''



def parse_results(checkHTTPDir,checkHTTPResultsDir):
	print ('    - Parse results')

	'''
	# Errors
	file = os.path.join(checkHTTPDir,'errors.json')
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
	utilitat.write_file(data,checkHTTPResultsDir,'errors.txt')

	# byStatus
	file = os.path.join(checkHTTPDir,'results.json')
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
		filename = '{}.txt'.format(code)
		utilitat.write_file(data,checkHTTPResultsDir,filename)

	# byTitle
	file = os.path.join(checkHTTPDir,'results.json')
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
	utilitat.write_file(data,checkHTTPResultsDir,'titles.txt')
	'''
	file = os.path.join(checkHTTPDir,'results.json')
	json = utilitat.read_json(file)

	# All login URLs
	login_urls = [
		p["url"] for v in json.values() for p in v["pages"] if p["login"]["found"]
	]
	utilitat.write_file('\n'.join(login_urls),checkHTTPResultsDir,'login_urls.txt')

	# HTTP login
	'''
	login_http = [
		url for url, v in json.items() if v.get("login_panel") and not v.get('login_HTTPS')
	]
	'''
	login_http = defaultdict(set)
	for url, v in json.items():
		for page in v['pages']:
			if page['login']['found'] and v['login_HTTPS'] == False:
				login_http[page['title'] or None].add(url)

	output = ''
	for title, urls in login_http.items():
		output += f'{title}\n'
		output += '\n'.join(urls)
		output += '\n\n'
	utilitat.write_file(output,checkHTTPResultsDir,'login_http.txt')

	# HTTPS login
	'''
	login_https = [
		url for url, v in json.items() if v.get("login_panel") and v.get('login_HTTPS')
	]
	'''
	login_https = defaultdict(set)
	for url, v in json.items():
		for page in v['pages']:
			if page['login']['found'] and v['login_HTTPS'] == True:
				login_https[page['title'] or None].add(url)
	output = ''
	for title, urls in login_https.items():
		output += f'{title}\n'
		output += '\n'.join(urls)
		output += '\n\n'

	utilitat.write_file(output,checkHTTPResultsDir,'login_https.txt')

	# Titols
	titles = defaultdict(set)
	for url, v in json.items():
		titles[v['title'] or None].add(url)

	output = ''
	for title, urls in titles.items():
		output += f'{title}\n'
		output += '\n'.join(urls)
		output += '\n\n'
	utilitat.write_file(output,checkHTTPResultsDir,'titles.txt')
	

def check_login(response):
	LOGIN_KEYWORDS = ['login','log in', 'sign in', 'username', 'password', 'passwd', 'authenticate', 'admin', 'portal']
	# HTTP 401 — fastest check
	if response.status_code == 401:
		auth = response.headers.get("WWW-Authenticate", "")
		return True, f"HTTP 401 — {auth}"

	html = BeautifulSoup(response.text, features="lxml")

	# Password input — most reliable
	for i in html.find_all("input"):
		if i.get("type", "").lower() == "password":
			return True, "Password input field detected"

	# Form action keyword
	for f in html.find_all("form"):
		action = f.get("action", "").lower()
		if any(kw in action for kw in LOGIN_KEYWORDS):
			return True, f"Form action: {action}"

	# Login link — href or javascript containing login keywords
	for a in html.find_all("a"):
		href = a.get("href", "").lower()
		text = a.get_text().lower().strip()
		if any(kw in href for kw in LOGIN_KEYWORDS):
			return True, f"Login link href: {a.get('href')}"
		if any(kw in text for kw in LOGIN_KEYWORDS):
			return True, f"Login link text: {text}"

	# Login button — input type submit or button
	for b in html.find_all(["button", "input"]):
		text = b.get_text().lower().strip()
		value = b.get("value", "").lower()
		if any(kw in text for kw in LOGIN_KEYWORDS):
			return True, f"Login button text: {text}"
		if any(kw in value for kw in LOGIN_KEYWORDS):
			return True, f"Login button value: {value}"

	# Title keyword
	title = html.find("title")
	if title and any(kw in title.text.lower() for kw in LOGIN_KEYWORDS):
		return True, f"Title match: {title.text.strip()}"

	return False, None

def extract_page_info(response, rtype):
    html     = BeautifulSoup(response.text, features="lxml")
    title    = html.find("title")

  
    # If 403 or 404 try to identify technology
    if response.status_code > 400 and not title:
    	title = html.find('address')

    #comments = re.findall(r'<!--[-]*(.*?)[-]*-->', response.text, re.DOTALL)

    # Login check
    has_login, reason = check_login(response)

    return {
        "url"      : response.url,
        "type"     : rtype,
        "status"   : response.status_code,
        "title"    : title.text.strip() if title else None,
        "server"   : response.headers.get("Server"),
        #"comments" : [c.strip() for c in comments if c.strip()],
        "login"    : {"found": has_login, "reason": reason},
    }

def extract_candidates(response, base_url):
    html       = BeautifulSoup(response.text, features="lxml")
    candidates = []

    # Meta refresh
    meta = html.find("meta", attrs={
        "http-equiv": lambda x: x and x.lower() == "refresh"
    })
    if meta:
        content = meta.get("content", "")
        match   = re.search(r'url=([^&\s]+)', content, re.IGNORECASE)
        if match:
            url = urljoin(response.url, match.group(1).strip())
            candidates.append(("meta", url))

    # JS location.href
    match = re.search(
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
        response.text
    )
    if match:
        url = urljoin(response.url, match.group(1))
        candidates.append(("js", url))

    # All frames — store all, not just last
    for frame in html.find_all("frame"):
        src = frame.get("src")
        if src:
            url = urljoin(response.url, src)
            candidates.append(("frame", url))

    return candidates

def follow_redirects(url,response):
	redirects = []
	current = response
	visited = set()
	queue = [("initial", response.url, response)]
	pages = []
	manual_check = []

	while queue:
		rtype, url, current = queue.pop(0)
		candidates = []
		html = BeautifulSoup(current.text, features='lxml')
		next_url = None

		if url in visited:
			continue
		visited.add(url)

		if current.status_code == 200:
			page = extract_page_info(current,rtype)
			pages.append(page)
			candidates = extract_candidates(current, url)

			for ctype, curl in candidates:
				if curl not in visited:
					try:
						r = requests.get(curl, timeout=10, verify=False, allow_redirects=True)
						if r.status_code == 200:
							queue.append((ctype, r.url, r))
						else:
							page2 = extract_page_info(r,ctype)
							pages.append(page2)
							
					except:
						page2 = extract_page_info(r,"error")
						pages.append(page2)
		else:
			page2 = extract_page_info(current,rtype)
			pages.append(page2)

	return pages
	

def check_availability(checkHTTPDir,UserAgent):
	print ('    - Check websites')
	file = os.path.join(checkHTTPDir,'urls.txt')
	urls = utilitat.read_file(file)
	results = {}
	errors = {}
	for url in urls:
		json_results = {'status':0,'title':'','login_HTTPS':None,'HTTPS':False}
		headers = {"User-Agent":UserAgent}
		try:
			response = requests.get(url,verify=False,allow_redirects=True,timeout=10,headers=headers)
		except Exception as e:
			t = type(e).__name__
			if t in errors.keys():
				errors[t].append(url)
			else:
				errors[t] = [url]
		else:
			# Redirect
			pages = follow_redirects(url,response)
			json_results['pages'] = pages

			
			for page in pages:
				# Aggregate logins
				if page['login']['found']:
					json_results['login_panel'] = True
					json_results['login_HTTPS'] = 'https://' in page['url']

			# Aggregate status code
			statuses = [p["status"] for p in pages if isinstance(p["status"], int)]
			json_results["status"] = 200 if 200 in statuses else (statuses[0] if statuses else None)
			
			# Aggregate titles
			titles = [p["title"] for p in pages if p.get("title") and p["title"].strip()]
			if not titles:
				servers = [p["server"] for p in pages if p.get("server") and p["server"].strip()]
				server = list(set(servers))
				json_results['title'] = server[0] if server else None
			else:
				title = list(set(titles))
				json_results["title"] = " | ".join(title)


			# HTTPS
			json_results["HTTPS"] = any("https://" in p["url"] for p in pages)


			results[url] = json_results

	utilitat.write_json(results,checkHTTPDir,'results.json')
	utilitat.write_json(errors,checkHTTPDir,'errors.json')

def get_scope(checkHTTPDir,resultsDir):
	print ('    - Get scope')
	file = os.path.join(resultsDir,'http.txt')
	ips = utilitat.read_file(file)
	data = ''
	first = True
	done = []
	for ip in ips:
		port = ip.split(':')[1]
		if port == '80' or port == '443':
			ip = ip.replace(':80','')
			ip = ip.replace(':443','')
		if ip not in done:
			if first:
				data = 'http://{}/'.format(ip)
				data = '{}\nhttps://{}/'.format(data,ip)
				first = False
			else:
				data = '{}\nhttp://{}/'.format(data,ip)
				data = '{}\nhttps://{}/'.format(data,ip)
			done.append(ip)
	utilitat.write_file(data,checkHTTPDir,'urls.txt')