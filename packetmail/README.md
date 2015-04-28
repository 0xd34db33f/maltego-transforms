# maltego-transforms-packetmail

Maltego transform for Packetmail.net. See code license for details (it's BSD, basically have fun)

Thanks to Nathan Fowler for the Packetmail service.

Configuration Steps:
1. Ask Nathan Fowler (nathan@packetmail.net) for an API key.
2. Place said API key into packetmail_api_key field in PacketmailTransforms.py
3. Make sure you have Python 2.7 and Requests module installed. For Requests information, please see http://docs.python-requests.org/en/latest/
4. Import packetmail.mtz into Maltego. This will give you a transform named "To Packetmail Abuse List" under "Other Transforms" for IP addresses.
5. Correct the fields of the "To Packetmail Abuse List" transform to conform to your local configuration.
6. Profi....ermm start looking up information.
