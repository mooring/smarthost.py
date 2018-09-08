# smarthost portal to mitmproxy

this is a simple portal smarthost to mitmproxy, It's still in developing, anyone like to join , please contat me

Usage : 

1. install mitmproxy by brew

```
brew install mitmproxy
```

in shell type the follow command, or just config it as a alias in ~/.bash_profile

```
mitmweb --anticache --confdir ~/.mitmproxy/ --anticomp --listen-port 8080 --anticomp -s "~/.mitmproxy/py/smarthost_4.py" --set smarthost=~/.mitmproxy/all_proxy.json
```

or in `~/.bash_profile`

```
alias proxy='mitmweb --anticache --confdir ~/.mitmproxy/ --anticomp --listen-port 8080 --anticomp -s "~/.mitmproxy/py/smarthost_4.py" --set smarthost=~/.mitmproxy/all_proxy.json'
```

then open a new terminal and  type

```
proxy
```


