# =====================================================
# ===== Please read following requirememnts first =====
# =====================================================
"""
Requirements: Python 3.6+
install modules: stix2, requests:
    pip install stix2, requests
"""
# =====================================================
# ======= Please read above requirememnts first =======
# =====================================================

from stix2ext import *
import stix2, requests, pprint

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTQyNTI2ODcsIm5iZiI6MTU1NDI1MjY4NywianRpIjoiODU5MDFhMGUtNDRjNC00NzEyLWJjNDYtY2FhMzg0OTU0MmVhIiwiaWRlbnRpdHkiOiJpbmZvc2VjIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.-Vb_TgjBkAKBcX_K3Ivq3H2N-sVkpIudJOi2a8mIwtI"
headers={'Authorization': 'Bearer '+ token}
api_url = "http://cybexp1.acs.unr.edu:5000/api/v1.0/related/"

r = requests.post(api_url, headers=headers, json = { "ipv4-addr" : "104.168.138.60" })
stix_bundle = stix2.parse(r.json())
print(stix_bundle)

stix_objects = stix_bundle["objects"]

related_objects_list = []
for stix_obj in stix_objects:
    if stix_obj["type"] == "relationship" : continue
    if stix_obj["objects"]["0"]["type"] == "ipv4-addr" : continue

    rel_obj = stix_obj["objects"]["0"]
    related_objects_list.append(rel_obj)

for rel_obj in related_objects_list:
    print(rel_obj)
