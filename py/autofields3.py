#Usage  : --scripts "autofields.py" --set autofields="config.json"
#Example: mitmproxy --scripts "~/.mitmproxy/py/autofields.py" --set autofields="~/.mitmproxy/auto_fields.json" --listen-port 8080
#Author : mooring 2018/04/26 17:00

import re, mimetypes, time, argparse, json, urllib
from os                 import path, mkdir, sep
from mitmproxy.http     import HTTPResponse
from mitmproxy          import ctx
from mitmproxy.net.http import Headers

LOG_TO_FILE = False


class AutoFields:
    def __init__(self):
        self.directory     = sep.join(path.dirname(__file__).split(sep)[:-1]) + sep
        self.reuse_header  = {}

    def log(self, _str):
        if LOG_TO_FILE:
            _path = self.directory + 'logs' + sep
            _file = '_'.join(time.asctime().split(' ')[:3]) + '.log'
            if not path.exists(_path): mkdir(_path, 755)
            open(_path + _file, 'a+').writelines(_str + '\n')
        else:
            ctx.log.warn(_str)

    def parse_fields_rule(self):
        if len(ctx.options.auto_fields) < 1: return
        confs     = {}
        home      = path.expanduser('~')
        conf_file = re.sub(r'^~', home, ctx.options.autofields)
        if path.exists(path.abspath(conf_file)):
            confs = json.loads(open(conf_file).read())
        else:
            self.log(conf_file + ' not exists')
            return
        for _host in confs:
            conf = confs[_host]
            self.reuse_header[_host] = {
                'matches'  : conf['matches'],
                'values'   : [],
                'is_query' : conf['is_query']  if 'is_query'  in conf else 0,
                'url_match': conf['url_match'] if 'url_match' in conf else ''
            }
        #self.log(json.dumps(self.reuse_header))

    def tampper_fields(self, flow):
        rules    = self.reuse_header
        req      = flow.request
        _host    = req.host
        _url     = req.pretty_url
        _headers = req.headers if req.headers is not None else {}
        _querys  = req.query   if req.query is not None else {}

        if _host in self.reuse_header:
            rule = self.reuse_header[_host]
            match, cnt, vals = rule['matches'], 0, []
            _check = _querys if rule['is_query'] == 1 else _headers

            if 'url_match' in rule :
                if _url.find(rule['url_match']) == -1:
                    return

            for k,v in enumerate(match):
                if v in _check and len(_check[v])>0:
                    cnt += 1; vals.append(_check[v])
            if cnt == len(match):
                self.reuse_header[_host]['values'] = vals
            elif len(rule['values']) == len(match):
                vals = self.reuse_header[_host]['values']
                for k, v in enumerate(match):
                    val = urllib.quote(vals[k].encode('utf-8'))
                    if rule['is_query'] == 1:
                        if _url.find(v +'=') >- 1:
                            _url = re.sub(r''.join([v,'=[^&]*?']), _url, r'%s%s<1>' % (v,val))
                        else:
                            flag = '&' if _url.find('?') != -1 else '?';
                            _url += '%s%s=%s' % (flag, v, val)
                    else:
                        req.request.headers[v] = vals[k]
                if rule['is_query'] == 1: 
                    header                   = Headers(host=_host)
                    header['location']       = _url
                    header["Connection"]     = 'closed'
                    header["Content-Length"] = '0'
                    flow.is_replay           = True
                    flow.response      = HTTPResponse(b"HTTP/1.1", 302, 'redirect temporary', header, b'', is_replay=True)


AutoField = AutoFields()

def load(l):
    l.add_option('autofields', str, '~/.mitmproxy/auto_fields.json', 'custom config file')

def request(flow):
    AutoField.tampper_fields(flow)

