### Kerberos web service testing environment

#### Architecture
```
+-----+
| KDC |    _____
+-----+-->/     \   +--------+
          | NET |<--| CLIENT |
+-----+-->\_____/   +--------+
| WEB |
| APP |
+-----+
```

#### Usage
In one terminal:
```
$ docker-compose build && docker-compose up
```
In another one:
```
$ docker exec -it (docker ps | grep client | cut -d ' ' -f 1) bash -c 'echo password | kinit user@LOCAL; klist'
Password for user@LOCAL:
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: user@LOCAL

Valid starting     Expires            Service principal
04/17/20 09:21:12  04/17/20 21:21:12  krbtgt/LOCAL@LOCAL
	renew until 04/18/20 09:21:12
$ docker exec -it (docker ps | grep client | cut -d ' ' -f 1) bash -c 'curl -v --negotiate -u user:password web.local/krb5hello'
*   Trying 172.21.0.3:80...
* TCP_NODELAY set
* Connected to web.local (172.21.0.3) port 80 (#0)
* Server auth using Negotiate with user 'user'
> GET /krb5hello HTTP/1.1
> Host: web.local
> Authorization: Negotiate ......
> User-Agent: curl/7.66.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Www-Authenticate: Negotiate ......
< Date: Mon, 20 Apr 2020 12:13:15 GMT
< Content-Length: 41
< Content-Type: text/plain; charset=utf-8
<
Hello, you used Kerberos authentication.
* Connection #0 to host web.local left intact
```
Remove leftovers:
```
$ docker-compose down
```
