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

from MaltegoTransform import MaltegoTransform

base_url = "https://www.packetmail.net/iprep.php/"
packetmail_api_key = "INSERT KEY HERE"

def ipToAbuseList(malEntityData, ipAddr):
    try:
        http_response = requests.get(base_url + ipAddr+ '?apikey=' + packetmail_api_key)
        jsonResponse = http_response.json()
        #Sanity check to make sure it appears we got some valid JSON data
        checkForOrigin = 'origin' in jsonResponse
        if checkForOrigin == False:
             raise Exception('Invalid JSON data detected from packetmail.net')
        if checkForOrigin == True:
	     for entities in jsonResponse.keys():
                  if 'source' in jsonResponse[entities]:
                       currEntity = malEntityData.addEntity("maltego.Website", '%s' % entities)
                       currEntity.addAdditionalFields(fieldName="URLS",displayName="URLs",value=jsonResponse[entities]['source']+' '+entities+'\n')
    except Exception,e:
        #Meh I'm just going to catch everything and let the user deal with it
        malEntityData.addEntity("maltego.Phrase", 'ipToAbuseList Error: - %s' % str(e))
    return malEntityData

### Main
if __name__ == '__main__':
    
    malEntityData = MaltegoTransform()
    results = ipToAbuseList(malEntityData, sys.argv[1])
    results.returnOutput()
