import json 
import time

def doNothing(data):
   return data



def misp_api_parser(data):
   return doNothing(data)

def unr_honeypot_parser(data):
   return doNothing(data)

def phishtank_api_parser(data):
   return doNothing(data)

def openphish_file_feed_parser(data):
   try:
      #if not comminity edition, payware
      json_object = json.loads(data) # should already be in json
      json_object["openphish_type"] = "premium"
      json_object["timestamp"] = time.time()
      return json.dumps(json_object)

   except ValueError: # else is community free version

      new_data = dict({"URLs": list(data.split()),
                        "timestamp": time.time(),
                        "openphish_type": "community"})
      return json.dumps(new_data)


