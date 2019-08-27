# API Reference

Temporary token for testing : ```eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1NTQyNTI2ODcsIm5iZiI6MTU1NDI1MjY4NywianRpIjoiODU5MDFhMGUtNDRjNC00NzEyLWJjNDYtY2FhMzg0OTU0MmVhIiwiaWRlbnRpdHkiOiJpbmZvc2VjIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.-Vb_TgjBkAKBcX_K3Ivq3H2N-sVkpIudJOi2a8mIwtI```

```
API URL: http://cybexp1.acs.unr.edu:5000

GET: http://cybexp1.acs.unr.edu:5000/api/v1.0/summary/attribute
GET: http://cybexp1.acs.unr.edu:5000/api/v1.0/summary/attribute/<att_type>
GET: http://cybexp1.acs.unr.edu:5000/api/v1.0/summary/event

GET: http://cybexp1.acs.unr.edu:5000/api/v1.0/event/features

POST: http://cybexp1.acs.unr.edu:5000/api/v1.0/related
POST: http://cybexp1.acs.unr.edu:5000/api/v1.0/related/attribute
POST: http://cybexp1.acs.unr.edu:5000/api/v1.0/related/attribute/summary

POST: http://cybexp1.acs.unr.edu:5000/api/v1.0/count
```

### Supported attribute types
```
"AS",
"asn",
"btc",
"bytes",
"campaign_id",
"campaign_name",
"checksum",
"city_name",
"comment",
"comp_algo",
"continent_code",
"country_code2",
"country_code3",
"country_name",
"cpe",
"creation_date",
"cryptocurrency_address",
"cve_id",
"data",
"datetime",
"description",
"dma_code",
"dns_soa_email",
"domain",
"email_addr",
"email_attachment_name",
"email_body",
"email_display_name",
"email_reply_to",
"encr_algo",
"filename",
"filepath",
"hash",
"height",
"hex_data",
"hostname",
"http_user_agent",
"id",
"imphash",
"ip",
"ipv4",
"jabber_id",
"kex_algo",
"latitude",
"location",
"longitude",
"mac_algo",
"machine_name",
"md5",
"message_id",
"mime_boundary",
"misp alias",
"mobile_app_id",
"mutex",
"name",
"named_pipe",
"nids",
"organization",
"other",
"password",
"pattern",
"pattern_in_file",
"pdb",
"pehash",
"phone_number",
"port",
"postal_code",
"premium_rate_telephone_number",
"protocol",
"prtn",
"pub_key_algo",
"region_code",
"region_name",
"registrar",
"regkey",
"repository",
"sessionid",
"sha1",
"sha224",
"sha256",
"sha384",
"sha512",
"sha512/224",
"sha512/256",
"shell_command",
"sigma",
"size_in_bytes",
"snort",
"ssdeep",
"ssh_client_env",
"ssh_version",
"subject",
"success",
"target_name",
"text",
"threat_actor_name",
"timezone",
"twitter_id",
"uri",
"url",
"user_agent",
"username",
"vulnerability",
"width"
"win_scheduled_task",
"win_service_displayname",
"win_service_name",
"x509_fingerprint",
"x509_fingerprint_md5",
"x509_fingerprint_sha1",
"x509_fingerprint_sha256",
"x_mailer",
"x_misp_target_external",
"x_misp_target_location",
"x_misp_target_org",
"x_misp_target_user",
"yara"
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
