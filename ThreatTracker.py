###############################################################
# ThreatTracker v1.0
# Script is designed to make periodic queries to a set of Google
# Custom Search Engines and generate alerts on new threats 
# identified.
#
# Author: @michael_yip
# Email: jiachongzhi@gmail.com
# Date: 2015-02-20
###############################################################
from apiclient.discovery import build
import pprint
import smtplib
import time
import glob
import os
from urllib2 import urlopen
import ConfigParser

###################### Configurations #########################
CSE_API_KEYS = []
SENDER_EMAIL = ""
SENDER_PASSWORD = ""
RECIPIENTS = []
SLEEP_SECONDS = 0 # This determines how often queries are made.
RULE_DIR = ""
PATH_TO_CONFIG = "config.ini"
###############################################################

# Keeps track of API keys used
NO_QUOTA_CSE_API_KEYS = []
CURRENT_WORKING_API = ""

########### List of Google Custom Search Engines ##############
# Search engine for malware definitions
AV_SEARCH_ENGINE_ID = "003089153695915392663:3aeplrxqc1q"
# Search engine for malware submissions
MALWARE_SEARCH_ENGINE_ID = "003089153695915392663:yi7j3xmja0w"
# Search engine for malware URLs
URL_SEARCH_ENGINE_ID = "003089153695915392663:8s9qiadkryk"
# Reverse WHOIS
WHOIS_SEARCH_ENGINE_ID = "003089153695915392663:5varpyppnfy"
# Google Safe Browsing API
SAFE_BROWSING_LOOKUP_URL = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=MalwareTracker&key={key}&appver=1.5.2&pver=3.1&url={url}"
SAFE_BROWSING_DIAGNOSTIC_URL = "https://www.google.com/safebrowsing/diagnostic?site="
###############################################################


def google(search_term, or_search_terms, search_engine_key, date_restrict="d30", start_index=1, page=1, results=None):
	global CURRENT_WORKING_API
	''' Search malware tracker CSE. '''
	
	print "[INFO] Searching for new results on '%s' - page %d ..." % (or_search_terms, page)
	results = results
	if not results: results = {}
		
	try:
		service = build("customsearch", "v1",
				developerKey=CURRENT_WORKING_API)

		res = service.cse().list(
			q = search_term,
			orTerms=or_search_terms,
			dateRestrict=date_restrict,
			start=start_index, # for pagination
			cx=search_engine_key,
		).execute()

		if res:
			try:
				if 'items' in res.keys():
					items = res['items']
					for item in items:
						link = item['link']
						title = item['title']
						snippet = item['htmlSnippet']
						if snippet:
							snippet = snippet.strip()
						# Cache results
						results[link] = {'title': title, 'link':link, 'snippet':snippet}
					
					# Next page
					if 'nextPage' in res['queries']:
						nextStartIndex = res['queries']['nextPage'][0]['startIndex']
						# Recurs through pages
						query_malware_tracker(search_term, or_search_terms, search_engine_key, date_restrict=date_restrict, start_index=nextStartIndex, page=(page+1), results=results)
			# Google sometimes throw error on next page results
			except Exception, e:
				print "[ERROR] An error has occurred while processing Google results."
				error = str(e)
				# Cascade exception
				if e.find("Daily Limit Exceeded") > -1 or error.find("Forbidden") > -1:
					print "[ERROR] Out of quota or forbidden..."
					print "[INFO] Cascading Daily Limit Exceeded error..."
					raise Exception(e)
				else:
					print error
	except Exception, e:
		print "[ERROR] An error has occurred while processing Google results."
		error = str(e)
		# If no quota left, try new key
		if error.find("Daily Limit Exceeded") > -1 or error.find("Forbidden") > -1:
			print "[ERROR] Out of quota or forbidden..."
			# If there are any API keys unused
			if not len(NO_QUOTA_CSE_API_KEYS) == len(CSE_API_KEYS):
				print "[INFO] Trying new key..."
				
				# Add current api key to no quota collection
				NO_QUOTA_CSE_API_KEYS.append(CURRENT_WORKING_API)
				
				# Find unused key and set as current working API
				unused_index = len(NO_QUOTA_CSE_API_KEYS)
				CURRENT_WORKING_API = CSE_API_KEYS[unused_index]
				
				# Retry with new API
				google(search_term, or_search_terms, search_engine_key, date_restrict=date_restrict, start_index=start_index, page=page, results=results)
		else:
			print error
	return results
	
def query_google_safe_browsing(domains, results=None):
	''' Check if domain is detected as infected. '''
	global CURRENT_WORKING_API, SAFE_BROWSING_LOOKUP_URL
	print "[INFO] Checking domain records on Google Safebrowsing ..."
	
	# Check if given domain is detected as 'malware'
	results = results
	if not results: results = {}
	# Unique domains only
	domains = set(domains)
	try:
		for domain in domains:
			print "[INFO] Checking %s..." % domain
			# Check safebrowsing API to see if domain is list as malware
			response = urlopen(SAFE_BROWSING_LOOKUP_URL.format(key=CURRENT_WORKING_API, url=domain)).read().decode("utf8")

			# If listed as malware
			if response == 'malware':
				results[domain] = {
									'title' : "%s is identified as malicious! Safe Browsing Diagnostic:" % (domain.replace('.', '[.]')),
									'link'  : SAFE_BROWSING_DIAGNOSTIC_URL + domain
								   }
	except Exception, e:
		print "[ERROR] An error has occurred while processing Google Safebrowsing results."
		error = str(e)
		# If no quota left, try new key
		if error.find("Daily Limit Exceeded") > -1 or error.find("Forbidden") > -1:
			print "[INFO] Out of quota or forbidden..."
			# If there are any API keys unused
			if not len(NO_QUOTA_CSE_API_KEYS) == len(CSE_API_KEYS):
				print "[INFO] Trying new key..."
				
				# Add current api key to no quota collection
				NO_QUOTA_CSE_API_KEYS.append(CURRENT_WORKING_API)
				
				# Find unused key and set as current working API
				unused_index = len(NO_QUOTA_CSE_API_KEYS)
				CURRENT_WORKING_API = CSE_API_KEYS[unused_index]
				
				# Retry with new API
				query_malware_tracker(search_term, or_search_terms, search_engine_key, date_restrict=date_restrict, start_index=start_index, page=page, results=results)
		else:
			print error
	return results
  
def email_alert(recipient, body, subject):
	''' Email alerts. '''
	global SENDER_EMAIL, SENDER_PASSWORD
	
	print "[INFO] Sending alerts to %s..." % recipient

	GMAIL_TEMPLATE =[
				 "From: " + "Malware Tracker <%s>" % SENDER_EMAIL,
				 "To: " + str( recipient ),
                 "MIME-version: 1.0",
				 "Subject: " + subject,
				 body ]
	
	template = "\n".join(GMAIL_TEMPLATE)
	
	# To send emails
	session = smtplib.SMTP('smtp.gmail.com', 587)
	session.ehlo()
	session.starttls()
	session.login(SENDER_EMAIL, SENDER_PASSWORD)
	session.sendmail(SENDER_EMAIL, recipient, template) 
	
def parse_rules():
	global RULE_DIR
	''' Parse rules. '''
	rule_files = glob.glob( os.path.join(RULE_DIR, "*.txt") )
	print "Parsing %d rule files..." % len(rule_files)
	
	search_objects = []
	for fn in rule_files:
		print "Parsing %s..." % fn
		with open(fn, "rb") as f:
			# Holder for search object
			search_object = {
								'rulename'    : "",
								'terms'       : [],
								'av_names'    : [],
								'url_patterns': [],
								'domains': [],
								'emails': []
							}
			lines = f.readlines()
			for line in lines:
				line = line.strip()
				# Skip lines that do not start with keywords
				if not line.startswith("Rulename##") and not line.startswith("Term##") and not line.startswith("AV##") and not line.startswith("URL##") and not line.startswith("Domain##") and not line.startswith("Email##"):
					continue
					
				if line.startswith("Rulename##"):
					s = line.split("##")
					search_object['rulename'] = s[1]
				if line.startswith("Term##"):
					s = line.split("##")
					search_object['terms'].append(s[1])
				if line.startswith("AV##"):
					s = line.split("##")
					search_object['av_names'].append(s[1])
				if line.startswith("URL##"):
					s = line.split("##")
					search_object['url_patterns'].append(s[1])
				if line.startswith("Domain##"):
					s = line.split("##")
					search_object['domains'].append(s[1])
				if line.startswith("Email##"):
					s = line.split("##")
					search_object['emails'].append(s[1])
			search_objects.append(search_object)
			f.close()
	return search_objects
	
def ConfigSectionMap(section):
	''' Configuration file parser. '''
	values = {}
	options = Config.options(section)
	for option in options:
		try:
			values[option] = Config.get(section, option)
		except:
			print "[ERROR] Trying to parse option: %s" % option
			values[option] = None
	return values
	
if __name__ == '__main__':
	try:
		# Read configuration file
		Config = ConfigParser.ConfigParser()
		Config.read(PATH_TO_CONFIG)
		
		# Parse configuration data
		RULE_DIR = ConfigSectionMap('Miscellaneous Settings')['rule_directory']
		SLEEP_SECONDS = ConfigSectionMap('Miscellaneous Settings')['cycle']
		SENDER_EMAIL = ConfigSectionMap('Email settings')['sender_email']
		SENDER_PASSWORD = ConfigSectionMap('Email settings')['sender_password']
		RECIPIENTS = ConfigSectionMap('Email settings')['recipients']
		CSE_API_KEYS = ConfigSectionMap('API')['cse_api_keys']
		
		# Convert data to lists
		RECIPIENTS = RECIPIENTS.replace('[','').replace(']','').replace('\n','').split(',')
		CSE_API_KEYS = CSE_API_KEYS.replace('[','').replace(']','').replace('\n','').split(',')
	except Exception as e:
		print "[ERROR] An error has occurred whilst parsing configuration file:"
		exit(e)
	
	# Set current working Google Custom Search Engine (CSE) API key
	CURRENT_WORKING_API = CSE_API_KEYS[0]
	
	# Keep listening out for hits
	while(True):
		# If there are hits not reported, email them				  
		search_term_objects = parse_rules()
	
		for term_obj in search_term_objects:
			# Search terms
			rule_name = term_obj['rulename']
			terms = term_obj['terms']
			av_names = term_obj['av_names']
			url_patterns = term_obj['url_patterns']
			domains = term_obj['domains']
			emails = term_obj['emails']
			
			# Construct OR search terms
			or_search_terms = []
			or_search_terms.extend(terms)
			or_search_terms.extend(av_names)
			or_search_terms.extend(url_patterns)
			or_search_terms.extend(domains)
			or_search_terms.extend(emails)
			
			# Search for results
			def_results = google(terms[0], " ".join(or_search_terms), AV_SEARCH_ENGINE_ID)
			sub_results = google(terms[0], " ".join(or_search_terms), MALWARE_SEARCH_ENGINE_ID)
			url_results = google(terms[0], " ".join(or_search_terms), URL_SEARCH_ENGINE_ID)
			domain_results = query_google_safe_browsing(domains)
			email_results = google(terms[0], " ".join(or_search_terms), WHOIS_SEARCH_ENGINE_ID)
			
			def_results_len = len(def_results.keys())
			sub_results_len = len(sub_results.keys())
			url_results_len = len(url_results.keys())
			domain_results_len = len(domain_results.keys())
			email_results_len = len(email_results.keys())
			
			# If no results, jump to next search term
			if def_results_len == 0 and sub_results_len == 0 and url_results_len == 0 and domain_results_len == 0 and email_results == 0:
				continue
			
			# Summary
			email_body = "== Malware Tracker search results over past 24 hours == \n\n"
			email_body += "Search terms included:\n\n"
			for term in set(or_search_terms):
				email_body += term.replace(".", "[.]") + "\n"
			email_body += "\n\n"
			if def_results_len > 0:
				email_body += "%d new AV definition(s) were identified as related to '%s'.\n\n" % (def_results_len, rule_name)
			if sub_results_len > 0:
				email_body += "%d new sample(s) submissions were identified as related to '%s'.\n\n" % (sub_results_len, rule_name)
			if url_results_len > 0:
				email_body += "%d new URL(s) were identified as related to '%s'.\n\n" % (url_results_len, rule_name)
			if domain_results_len > 0:
				email_body += "%d '%s' related domain(s) were identified as malicious.\n\n" % (domain_results_len, rule_name)
			if email_results_len > 0:
				email_body += "%d domain(s) were identified to the email handle(s).\n\n" % (email_results_len, rule_name)
			email_body += "---------------------------------------------------------------\n\n"
			
			# Results
			email_body += "== AV definitions ==\n\n"
			if len(def_results.keys()) > 0:
				for k, r in def_results.items():
					email_body += r['title'] + "\n"
					email_body += r['link'] + "\n"
					email_body += r['snippet'] + "\n"
					email_body += "\n\n"
			else:
				email_body += "No new relevant AV definitions found.\n\n"
			email_body += "---------------------------------------------------------------\n\n\n"
			
			email_body += "== Sample submissions ==\n\n"
			if len(sub_results.keys()) > 0:
				for k, r in sub_results.items():
					email_body += r['title'] + "\n"
					email_body += r['link'] + "\n"
					email_body += r['snippet'] + "\n"
					email_body += "\n\n"
			else:
				email_body += "No new relevant sample submissions found.\n\n"
			email_body += "---------------------------------------------------------------\n\n\n"
			
			email_body += "== Malicious URLs ==\n\n"
			if len(url_results.keys()) > 0:
				for k, r in url_results.items():
					email_body += r['title'] + "\n"
					email_body += r['link'] + "\n"
					email_body += r['snippet'] + "\n"
					email_body += "\n\n"
			else:
				email_body += "No new relevant malicious URLs found.\n\n"
			email_body += "---------------------------------------------------------------\n\n\n"
			
			email_body += "== Malicious domains ==\n\n"
			if len(domain_results.keys()) > 0:
				for k, r in domain_results.items():
					email_body += r['title'] + "\n"
					email_body += r['link'] + "\n"
					email_body += "\n\n"
			else:
				email_body += "No new relevant malicious URLs found.\n\n"
			email_body += "---------------------------------------------------------------\n\n\n"
			
			email_body += "== Reverse WHOIS ==\n\n"
			if len(email_results.keys()) > 0:
				for k, r in email_results.items():
					email_body += r['title'] + "\n"
					email_body += r['link'] + "\n"
					email_body += "\n\n"
			else:
				email_body += "No new relevant malicious URLs found.\n\n"
			email_body += "---------------------------------------------------------------\n\n\n"
			
			for recipient in RECIPIENTS:
				if len(recipient) > 0:
					# Email results
					email_alert(recipient, email_body, "Malware Tracker Alert for '%s'" % rule_name)
		
		# Runs every 6 hours
		print "[INFO] Sleeping for 6 hours...."
		time.sleep(float(SLEEP_SECONDS)) 