#!/usr/bin/python

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
DISCLAIMED. IN NO EVENT SHALL RYAN KEYES, HIS EMPLOYER, OR ISIGHT PARTNERS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import requests
import hmac
import traceback
import string
import hashlib
import json
import time
import email
import sys

from MaltegoTransform import MaltegoTransform

url = 'https://api.isightpartners.com'
pubKey = 'INSERT PUBKEY HERE'
privKey = 'INSERT PRIVKEY HERE'
apiVer = '2.0'

# Get the HTTP authentication headers.
def getAuthHeaders(authKey, respFormat, timestamp):
   authHeaders = {
   	'X-Auth' : pubKey,
   	'X-Auth-Hash' : hmac.new(privKey, authKey, hashlib.sha256).hexdigest(),
   	'Accept' : respFormat,
   	'Accept-Version' : apiVer,
   	'Date' : timestamp
   }
   return authHeaders

# Get past 24 hours of IOCs from iSIGHT.
def getJSON(endpoint,query,queryVars):

   # Submit request to iSIGHT's API and get the resulting IOCs. 
   respFormat = 'application/json'
   timestamp = email.Utils.formatdate(localtime=True)
   authKey = endpoint + query + apiVer + respFormat + timestamp
   	
   # Get the HTTP authentication headers.
   authHeaders = getAuthHeaders(authKey, respFormat, timestamp)
   
   req = requests.get(url+endpoint,params=queryVars, headers=authHeaders, verify=True)
   try:
      jsonData = json.loads(req.text)
   except Exception,e:
      #Moving on
      jsonData = {}
   return jsonData

def formatURLs(x,y):
   return x+'\n'+y

# Modify this function for development/troubleshooting.
def ipToReport(malEntityData, ip):
   urlLookup = {}
   query = '?ip='+ip
   queryVars = {
                        'ip':ip
                }
   
   try:
      jsonData = getJSON('/search/basic',query,queryVars)
      if 'message' in jsonData.keys():
         jsonMessage = jsonData[u'message']
         for jsonReport in jsonMessage:
            if 'title' in jsonReport.keys():
               title = jsonReport[u'title']
               if not title in urlLookup:
                  urlLookup[title] = []
               urlLookup[title].append(jsonReport[u'webLink']+u' '+ title)

         for k,v in urlLookup.iteritems():
            currEntity = malEntityData.addEntity("maltego.Website", '%s' % k)
            urlField = reduce(formatURLs,v)
            currEntity.addAdditionalFields(fieldName="URLS",displayName="URLs",value=urlField)
   except Exception,e:
      #Meh I'm just going to catch everything and let the user deal with it
      malEntityData.addEntity("maltego.Phrase", 'ipToAbuseList Error: - %s' % str(e))

   return malEntityData

def ipToPivot(malEntityData, ip):
   urlLookup = {}
   try:
      jsonData = getJSON('/pivot/indicator/ip/'+ip,'','')

      if 'message' in jsonData.keys():
         jsonMessage = jsonData[u'message']
         indicators = jsonMessage[u'publishedIndicators']
         for jsonReport in indicators:
            if jsonReport[u'domain'] is not None:
               currEntity = malEntityData.addEntity("maltego.Domain", '%s' % jsonReport[u'domain'])
            if jsonReport[u'ip'] is not None:
               currEntity = malEntityData.addEntity("maltego.IPv4Address", '%s' % jsonReport[u'ip'])
            if jsonReport[u'md5'] is not None:
               currEntity = malEntityData.addEntity("maltego.Phrase",'%s' %jsonReport[u'md5'])
   except Exception,e:
      #Meh I'm just going to catch everything and let the user deal with it
      malEntityData.addEntity("maltego.Phrase", 'ipToAbuseList Error: - %s' % str(e))

   return malEntityData

def domainToReport(malEntityData, domain):
   urlLookup = {}
   query = '?domain='+domain
   queryVars = {
                        'domain':domain
                }

   try:
      jsonData = getJSON('/search/basic',query,queryVars)
      if 'message' in jsonData.keys():
         jsonMessage = jsonData[u'message']
         for jsonReport in jsonMessage:
            if 'title' in jsonReport.keys():
               title = jsonReport[u'title']
               if not title in urlLookup:
                  urlLookup[title] = []
               urlLookup[title].append(jsonReport[u'webLink']+u' '+ title)

         for k,v in urlLookup.iteritems():
            currEntity = malEntityData.addEntity("maltego.Website", '%s' % k)
            urlField = reduce(formatURLs,v)
            currEntity.addAdditionalFields(fieldName="URLS",displayName="URLs",value=urlField)
   except Exception,e:
      #Meh I'm just going to catch everything and let the user deal with it
      malEntityData.addEntity("maltego.Phrase", 'ipToAbuseList Error: - %s' % str(e))

   return malEntityData

def domainToPivot(malEntityData, domain):
   urlLookup = {}
   try:
      jsonData = getJSON('/pivot/indicator/domain/'+domain,'','')

      if 'message' in jsonData.keys():
         jsonMessage = jsonData[u'message']
         indicators = jsonMessage[u'publishedIndicators']
         for jsonReport in indicators:
            if jsonReport[u'domain'] is not None:
               currEntity = malEntityData.addEntity("maltego.Domain", '%s' % jsonReport[u'domain'])
            if jsonReport[u'ip'] is not None:
               currEntity = malEntityData.addEntity("maltego.IPv4Address", '%s' % jsonReport[u'ip'])
            if jsonReport[u'md5'] is not None:
               currEntity = malEntityData.addEntity("maltego.Phrase",'%s' %jsonReport[u'md5'])
   except Exception,e:
      #Meh I'm just going to catch everything and let the user deal with it
      malEntityData.addEntity("maltego.Phrase", 'ipToAbuseList Error: - %s' % str(e))

   return malEntityData

transformFunctions = {
   'ipToReport': ipToReport,
   'ipToPivot': ipToPivot,
   'domainToReport': domainToReport,
   'domainToPivot': domainToPivot,
}

# Main
if __name__ == '__main__':
   transformName = sys.argv[1]
   dataToTransform = sys.argv[2]

   malEntity = MaltegoTransform()
   results = transformFunctions[transformName](malEntity,dataToTransform)
   results.returnOutput()
