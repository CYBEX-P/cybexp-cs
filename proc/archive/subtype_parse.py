import json 


def doNothing(data):
   return data



def misp_api_parser(data):
   return doNothing(data)

def unr_honeypot_parser(data):
   return doNothing(data)

def phishtank_api_parser(data):
   return doNothing(data)

def openphish_file_feed_parser(data):
   new_data = dict({"URLs": list(data.split())})
   return json.dumps(new_data)


