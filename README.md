# LEAPI

LEAPI is a clustered server API system, written in Go, for managing Lets Encrypt certificate renewals.

LEAPI uses the excellent [getssl](https://github.com/srvrco/getssl) Bash script for the actual renewal of certificates.

It can be used on a single server, but is particularly useful for clusters of servers, with many domains.
You can use it standalone, for acquiring/renewing certificates for non web services, or with an external webserver like Nginx, Caddy, etc.

LEAPI operates in a multi-master configuration. When you add or delete a server or domain on any server, it automatically replicates the changes to all other servers, and renews your certificate. Replication is accomplished via HTTP.

## Endpoints:

```[GET]  https://leapiserver.tld/api/servers``` --- List Servers

```[PUT]  https://leapiserver.tld/api/servers/web1.mydomain.com``` --- Add New Server

```[GET]  https://leapiserver.tld/api/domains``` --- List Domains

```[POST] https://leapiserver.tld/api/domains/mycoolsite.com``` --- Add New Domain

```[POST] https://leapiserver.tld/api/renew``` --- Force Renewal

```[GET]  https://leapiserver.tld/up``` --- Uptime Check

## Install
- Download the LEAPI binary, or build from source.
- Copy it to ```/opt/leapi```
- You may use the included SystemD service file if you use a SystemD based distribution.
- Edit the ```leapi_config.json``` file for your needs, leaving ```production``` set to ```false``` until setup is complete, and copy it to ```/opt/leapi``` or ```/etc```.
- Install getssl with ```curl --silent https://raw.githubusercontent.com/srvrco/getssl/latest/getssl > /opt/leapi/getssl ; chmod 700 /opt/leapi/getssl```
- Create the base config for getssl: ```/opt/leapi/getssl -w /opt/leapi -c mycoolsite.com```
- Start LEAPI, either from the commandline or with ```systemctl start leapi```
- Add your servers via the LEAPI API: 
(You don't necessarily have to do this on the server itself.)
```
curl -X PUT http://localhost/api/servers/server1.mydomain.com -H 'Authorization: Bearer mySeCrEtKeY'
curl -X PUT http://localhost/api/servers/server2.mydomain.com -H 'Authorization: Bearer mySeCrEtKeY'
curl -X PUT http://localhost/api/servers/server3.mydomain.com -H 'Authorization: Bearer mySeCrEtKeY'
```
- Add your domains via the LEAPI API:
```
curl -X PUT http://localhost/api/domains/mycoolsite.com -H 'Authorization: Bearer mySeCrEtKeY'
curl -X PUT http://localhost/api/domains/myothersite.com -H 'Authorization: Bearer mySeCrEtKeY'
```
- Assuming there were no errors, edit your ```leapi_config.json``` file and change ```production``` to ```true```.
- Force a renewal via the API:
    curl -X POST http://localhost/api/renew -H 'Authorization: Bearer mySeCrEtKeY'




