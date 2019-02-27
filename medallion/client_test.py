from taxii2client import Server
server = Server('http://localhost:5000/taxii/', user='admin', password='Password0')
api_root = server.api_roots[0]
collection = api_root.collections[0]
e = collection.get_object("observed-data--13338ddf-007b-4973-ae32-651a1fa61a5d")
from pprint import pprint
pprint(e)
