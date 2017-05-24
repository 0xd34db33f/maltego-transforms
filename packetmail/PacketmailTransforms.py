'''
Copyright (c) 2015, Ryan Keyes
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL RYAN KEYES OR HIS EMPLOYER BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import os, sys
import requests
import json
import re

from MaltegoTransform import MaltegoTransform
from credentials import Credentials
from config import Proxies

creds = Credentials()
packetmailApiKey = str(creds.getCredentials('PACKETMAIL',u'packetmailApiKey'))
proxyList = Proxies()
baseUrl = "https://www.packetmail.net/iprep.php/"


def ipToAbuseList(malEntityData, ipAddr):
	try:
                httpResponse = requests.get(baseUrl + ipAddr+ '?apikey=' + packetmailApiKey, proxies = proxyList.getProxies())
		#httpResponse = requests.get(baseUrl + ipAddr+ '?apikey=' + packetmailApiKey)
		jsonResponse = httpResponse.json()
		#Sanity check to make sure it appears we got some valid JSON data
		checkForOrigin = 'origin' in jsonResponse
		if checkForOrigin == False:
			raise Exception('Invalid JSON data detected from packetmail.net')
		if checkForOrigin == True:
			for entities in jsonResponse.keys():
				if entities == 'MaxMind_Free_GeoIP':
					currEntity = malEntityData.addEntity("maltego.Location", '%s' % entities)
					if jsonResponse[entities][0].get('country_name'):
						currEntity.addAdditionalFields(fieldName="country",displayName="Country",value=str(jsonResponse[entities][0]['country_name']))
					if jsonResponse[entities][0].get('city'):
						currEntity.addAdditionalFields(fieldName="city",displayName="City",value=str(jsonResponse[entities][0]['city']))
					if jsonResponse[entities][0].get('country_code'):
						currEntity.addAdditionalFields(fieldName="countrycode",displayName="Country Code",value=jsonResponse[entities][0]['country_code']+'\n')
					if jsonResponse[entities][0].get('longitude'):
						currEntity.addAdditionalFields(fieldName="longitude",displayName="Longitude",value=str(jsonResponse[entities][0]['longitude'])+'\n')
					if jsonResponse[entities][0].get('latitude'):
						currEntity.addAdditionalFields(fieldName="latitude",displayName="Latitude",value=str(jsonResponse[entities][0]['latitude'])+'\n')
					currEntity.addAdditionalFields(fieldName="source",displayName="Source",value='%s' % entities)
				if 'source' in jsonResponse[entities] and not entities == "disclaimer":
					currEntity = malEntityData.addEntity("maltego.Website", '%s' % entities)
					currEntity.addAdditionalFields(fieldName="Feed",displayName="Feed Name",value=entities+'\n')
					currEntity.addAdditionalFields(fieldName="URLS",displayName="URLs",value=jsonResponse[entities]['source']+'\n')
					if jsonResponse[entities].get('last_seen'):
						currEntity.addAdditionalFields('link#maltego.link.label','Label','Last Seen',value=jsonResponse[entities]['last_seen']+'\n')
					context = ''
					if isinstance((jsonResponse[entities]['context']), basestring) is True:
						hash_value = ''
						hash_type = ''
						MD5 = ''
						SHA1 = ''
						SHA256 = ''
						MD5_search = re.search(r'([a-f0-9]{32}|[A-F0-9]{32})', (jsonResponse[entities]['context']))
						SHA1_search = re.search(r'([a-f0-9]{40}|[A-F0-9]{40})', (jsonResponse[entities]['context']))
						SHA256_search = re.search(r'([a-f0-9]{64}|[A-F0-9]{64})',
                                  (jsonResponse[entities]['context']))
						if SHA256_search:
							currEntity.addAdditionalFields(fieldName="SHA256",displayName="SHA256",value=SHA256_search.group(1)+'\n')
							hash_value = SHA256_search.group(1)
							hash_type = 'SHA256'
						if MD5_search and hash_value is '':
							currEntity.addAdditionalFields(fieldName="MD5",displayName="MD5",value=MD5_search.group(1)+'\n')
							hash_value = MD5_search.group(1)
							hash_type = 'MD5'
						if SHA1_search and hash_value is '':
							currEntity.addAdditionalFields(fieldName="SHA1",displayName="SHA1",value=SHA1_search.group(1)+'\n')
							hash_value = SHA1_search.group(1)
							hash_type = 'SHA1'
						if hash_value is '':
							context = (jsonResponse[entities]['context'])
						else:
							context = "Malware"
							currEntity = malEntityData.addEntity("maltego.Hash", '%s' % hash_value)
							currEntity.addAdditionalFields(fieldName="type",displayName="Hash Type",value='%s' % hash_type+'\n')

							currEntity.addAdditionalFields(fieldName="Feed",displayName="Feed Name",value=entities+'\n')
							currEntity.addAdditionalFields(fieldName="URL",displayName="Source URL",value=jsonResponse[entities]['source']+'\n')
							if jsonResponse[entities].get('last_seen'):
								currEntity.addAdditionalFields('link#maltego.link.label','Label','Last Seen',value=jsonResponse[entities]['last_seen']+'\n')
					else:
						if jsonResponse[entities]['context'][0].get('category'):
							cat_context = str(jsonResponse[entities]['context'][0]['category'])
							context = "Category - " + (jsonResponse[entities]['context'][0]['category']) + " "
						if jsonResponse[entities]['context'][0].get('signature'):
							context = context + "Signature - " + (jsonResponse[entities]['context'][0]['signature']) + " "
						if entities == "seclytics_daily":
							context = ' - '.join(jsonResponse[entities]['context'][0]['categories'])
					currEntity.addAdditionalFields(fieldName="Context",displayName="Context",value=context+'\n')

	except Exception,e:
		#Meh I'm just going to catch everything and let the user deal with it
		malEntityData.addEntity("maltego.Phrase", 'ipToAbuseList Error: - %s' % str(e))
	return malEntityData

### Main
if __name__ == '__main__':
    
	malEntityData = MaltegoTransform()
	results = ipToAbuseList(malEntityData, sys.argv[1])
	results.returnOutput()
