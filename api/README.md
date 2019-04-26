# API Reference

Temporary token for testing : ```eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTQyNTI2ODcsIm5iZiI6MTU1NDI1MjY4NywianRpIjoiODU5MDFhMGUtNDRjNC00NzEyLWJjNDYtY2FhMzg0OTU0MmVhIiwiaWRlbnRpdHkiOiJpbmZvc2VjIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.-Vb_TgjBkAKBcX_K3Ivq3H2N-sVkpIudJOi2a8mIwtI```

### Supported attributes
```
{
'ip' : 'ipv4-addr',
'ipv4' : 'ipv4-addr',
'ipv4-addr' : 'ipv4-addr',
'url':'url',
'email' : 'email-addr',
'email-addr' : 'email-addr',
'domain-name' : 'domain-name',
'domain' : 'domain-name',
'mac-addr' : 'mac-addr',
'mac' : 'mac-addr',
'file' : 'file',
'file-hash' : 'file',
'file-sha256' : 'file',
'file-hash-sha256' : 'file'
'port' : 'port',
'btc' : 'btc',
'BTC' : 'btc',
'autonomous-system' : 'autonomous-system',
'AS' : 'autonomous-system',
'BGP' : 'bgp-path',
'bgp-path' : 'bgp-path',
'ssid' : 'ssid',
'comment' : 'comment'
}
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
{ "ip" : "88.214.26.89", "from" : "2018/4/1 00:00", "to" : "2020/4/1 12:00", "timezone" : "US/Pacific" }
{ "ipv4-addr" : "104.168.138.60", "from" : "2019/4/1 00:00" }
{ "ipv4-addr" : "88.214.26.89",  "to" : "2019/3/20"}
{ "url" : "http://165.227.0.144:80/bins/rift.x86", "from" : "2019/4/1 00:00", "to" : "2019/4/1 12:00", "timezone" : "US/Pacific" }
{ "email" : "johndoe@example.com"}
```
#### Example Response:
```
{
    "objects": [
        {
            "created_by_ref": "identity--7f60ac36-74dd-4c23-bc31-3226533d93d2",
            "created": "2019-04-26T19:20:18.894Z",
            "type": "observed-data",
            "id": "observed-data--d35066c3-78d3-4035-82d7-6b61345e50d7",
            "first_observed": "2019-02-26T05:09:14.017262Z",
            "objects": {
                "0": {
                    "value": "88.214.26.89",
                    "type": "ipv4-addr"
                }
            },
            "modified": "2019-04-26T19:20:18.894Z",
            "number_observed": 10000,
            "last_observed": "2019-04-26T19:15:19.749Z"
        }
    ],
    "type": "bundle",
    "id": "bundle--186265b5-b7b6-4c36-b32f-46dbe9f602fa",
    "spec_version": "2.0"
}
```
**number_observed** is limited to **10,000** which means it will stop counting if it sees the attribute for more than 10,000 times. This is done for faster response
### GET JWT Token
