# smarthost portal to mitmproxy

this is a simple portal smarthost to mitmproxy, It's still in developing, anyone like to join , please contat me

Usage : 
in shell type the follow command, or just config it as a alias in ~/.bash_profile

```
mitmweb --anticache --cadir ~/.mitmproxy/cert/ --stream 512k --host --anticomp --port 8080 -z -s "~/.mitmproxy/py/smarthost_2.py ~/.mitmproxy/all_proxy.json"
```

or in `~/.bash_profile`

```
alias proxy='mitmweb --anticache --cadir ~/.mitmproxy/cert/ --stream 512k --host --anticomp --port 8080 -z -s "~/.mitmproxy/py/smarthost_2.py ~/.mitmproxy/all_proxy.json"'
```

then in terminal just type

```
proxy
```


