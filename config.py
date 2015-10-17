import configparser

class Proxies:

	http_proxy = None
	https_proxy = None
	config = None
	def __init__(self):
		self.config = configparser.ConfigParser()
		self.config.read('proxies.cfg')
		self.http_proxy = str(self.config['PROXYLIST'][u'http'])
		self.https_proxy = str(self.config['PROXYLIST'][u'https'])

	def getProxies(self):
		proxyDict = { 
              		"http"  : self.http_proxy, 
              		"https" : self.https_proxy, 
            	}
		return proxyDict

