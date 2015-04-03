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
import urllib2

import os.path as path
import time

from MaltegoTransform import MaltegoTransform

def downloadUpdatedList():
   try:
      httpResponse = urllib2.urlopen("https://check.torproject.org/exit-addresses")
      outputFile = open("exit-addresses",'w')
      outputFile.write(httpResponse.read())
      outputFile.close()
      httpResponse.close()
   except Exception,e:
      print e

def ipToTorList(malEntityData, ipAddr):
   try:
      if not path.isfile('exit-addresses') or (time.time()-path.getmtime('exit-addresses'))/60 > 120:
         downloadUpdatedList()
      with open('exit-addresses','r') as dataFile:
            for line in dataFile:
               if line.startswith('ExitAddress %s' % ipAddr):
                  currEntity = malEntityData.addEntity("maltego.Phrase", 'Tor Exit Node')
   except Exception,e:
      #Meh I'm just going to catch everything and let the user deal with it
      malEntityData.addEntity("maltego.Phrase", 'ipToAbuseList Error: - %s' % str(e))
   return malEntityData

### Main
if __name__ == '__main__':
    
    malEntityData = MaltegoTransform()
    results = ipToTorList(malEntityData, sys.argv[1])
    results.returnOutput()
