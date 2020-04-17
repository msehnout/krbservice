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
...
```
Remove leftovers:
```
$ docker-compose down
```
