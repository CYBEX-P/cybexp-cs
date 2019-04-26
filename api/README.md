# API Reference

Temporary token for testing : ```eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTQyNTI2ODcsIm5iZiI6MTU1NDI1MjY4NywianRpIjoiODU5MDFhMGUtNDRjNC00NzEyLWJjNDYtY2FhMzg0OTU0MmVhIiwiaWRlbnRpdHkiOiJpbmZvc2VjIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.-Vb_TgjBkAKBcX_K3Ivq3H2N-sVkpIudJOi2a8mIwtI```

### Supported attributes
```
ipv4-addr
url
```

### Query : GET Related Objects to an Attribute =========================
#### Query Format
```
url = http://cybexp1.acs.unr.edu:5000/api/v1.0/related/
method = POST
Authorization Header : Bearer <JWT Token>
Body:
    content-type: application/json
    data: { <attribute type> : <attribute value> }
```


#### Example JSON Body:
###### IP Address:
```
{ "ip" : "104.168.138.60"
{ "ipv4-addr" : "104.168.138.60" }
{ "url" : "http://165.227.0.144:80/bins/rift.x86"}
{ "file" : "bf69f4219069098da61a80641265d8834b474474957742510105d70703ebdb27" }
{ "file-hash" : "bf69f4219069098da61a80641265d8834b474474957742510105d70703ebdb27" }
{ "file-sha256" : "bf69f4219069098da61a80641265d8834b474474957742510105d70703ebdb27" }
```


### Query : Count Attribute in Time Range =========================
#### Query Format
```
url = http://cybexp1.acs.unr.edu:5000/api/v1.0/count/
method = POST
Authorization Header : Bearer <JWT Token>
Body:
    content-type: application/json
	Mandatory parameters : <attribute type>
	Optional parameters : "from", "to", "timezone"
    data: { "<attribute type>" : "<attribute value>", "from" : "<From date time>", "to" : "<To date time>", "timezone" : <Timezone> }
```


#### Example JSON Body:
```
{ "ipv4-addr" : "104.168.138.60", "from" : "2019/4/1 00:00" }
{ "ipv4-addr" : "88.214.26.89",  "to" : "2019/3/20"}
{ "url" : "http://165.227.0.144:80/bins/rift.x86", "from" : "2019/4/1 00:00", "to" : "2019/4/1 12:00", "timezone" : "US/Pacific" }
```

### GET JWT Token
