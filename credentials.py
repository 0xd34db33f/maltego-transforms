import configparser

class Credentials:

	config = None
	def __init__(self):
		self.config = configparser.ConfigParser()
		self.config.read('credentials.cfg')

	def getCredentials(self,parentModuleName,credentialName):
		return self.config[parentModuleName][credentialName]

