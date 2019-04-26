# API Reference

### 

### GET Related Objects to an Attribute
#### Supported attributes
```
ipv4-addr
url
```
#### Query Format
```
url = http://cybexp1.acs.unr.edu:5000/api/v1.0/related/
method = POST
Authorization Header : Bearer <JWT Token>
Body:
    content-type: application/json
    data: { <attribute type> : <attribute value> }
```
Temporary token for testing : ```eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTQyNTI2ODcsIm5iZiI6MTU1NDI1MjY4NywianRpIjoiODU5MDFhMGUtNDRjNC00NzEyLWJjNDYtY2FhMzg0OTU0MmVhIiwiaWRlbnRpdHkiOiJpbmZvc2VjIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.-Vb_TgjBkAKBcX_K3Ivq3H2N-sVkpIudJOi2a8mIwtI```

#### Example JSON Body:

###### IP Address:
```{ "ipv4-addr" : "104.168.138.60" }```

###### URL:
```{ "url" : "http://165.227.0.144:80/bins/rift.x86"}```





### GET JWT Token
