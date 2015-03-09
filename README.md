ThreatTracker is a IOC tracker written in Python. 

The script queries 4 Google Custom Search Engines periodically to identify new:

1) AV definitions - https://www.google.co.uk/cse/publicurl?cx=003089153695915392663:3aeplrxqc1q
2) Malware sample submissions - https://www.google.co.uk/cse/publicurl?cx=003089153695915392663:yi7j3xmja0w
3) Malicious URLs and domains - https://www.google.co.uk/cse/publicurl?cx=003089153695915392663:8s9qiadkryk
4) Reverse WHOIS - https://www.google.co.uk/cse/publicurl?cx=003089153695915392663:5varpyppnfy

The script also monitors the status of domains using the Google Safe Browsing Lookup API and Google Safebrowsing Diagnosis Page.

Requirements:

	1) Google APIs Client Library for Python - https://developers.google.com/api-client-library/python/start/installation
	2) Google API key(s)
	3) To use the script, rules must be created in the /rules directory. 
	Note: A sample rule (for tracking Dridex) is created to highlight the fomart required.

This project is still in beta and so if you have found a bug, please do let me know :-)

Please feel free to email me should you have any questions. I am always on the look out for new data sources and new ideas!



