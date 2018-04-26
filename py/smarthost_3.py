#Usage  : -s "smarthost.py map_config.json"
#Example: mitmproxy -s "smarthost.py /path/to/request/map/config.json" --port 8080
#Author : mooring 2017/11/29 09:08AM

import re, mimetypes, time, json, ipaddress
from os                 import path, mkdir, sep
from mitmproxy.http     import HTTPResponse
from mitmproxy          import ctx
from mitmproxy.net.http import Headers


LOG_TO_FILE, FLOW_LIST_MAX_NUMBER = False, 3000
DEFAULT_PROXY = None  # accept tupple or None , example: ('dev-proxy.oa.com', 8080)


class Smarthost:
    def __init__(self):
        self.directory     = sep.join(path.dirname(__file__).split(sep)[:-1]) + sep
        self.local_rule    = {}
        self.remote_rule   = {}
        self.reuse_header  = {}
        self.flow_count    = 0
        self.init_smarthost_server()


    def route_proxy(self, flow):
        _host, src_ip = flow.request.host, None
        if flow.client_conn: src_ip = flow.client_conn.address[0].split(':')[-1]
        if _host == 'config.qq.com':
            self.server_smarthost(flow)
        else:
            if src_ip in self.remote_rule:
                self.remote_proxy_tamper(flow, src_ip)   #;self.log('fall in remote_rule')
            elif _host in self.local_rule:
                self.map_local_file(flow)                #;self.log('fall in local_rule')
            else:
                self.map_local_file(flow)                #;self.log('default to map_local')

    def remote_proxy_tamper(self, flow, src_ip):
        if flow.live:
            (_host, cur_rule, pathname) = flow.request.host, self.remote_rule[src_ip], flow.request.path
            if cur_rule['model'] == 'local' and _host in cur_rule and len(cur_rule[_host]) > 0:
                self.proxy_request_to_upstream(flow, (cur_rule[_host], 80))
                self.log('request %s has been hosted to %s with query path\n%s\n%s\n%s\n'
                    % (_host, cur_rule[_host], '-'*80, pathname, '-'*80))
            elif cur_rule['model'] == 'remote' and cur_rule['proxy']:
                self.proxy_request_to_upstream(flow, cur_rule['proxy'])
                self.log('request %s has been redirected to %s width port %d with query path\n%s\n%s\n%s\n'
                    % (_host, cur_rule['proxy'][0], cur_rule['proxy'][1], '-'*80, pathname, '-'*80))
            else:
                self.map_local_file(flow)  # ;self.log('proxy tamper failed to map local file 1')
        else:
            self.map_local_file(flow)      # ;self.log('proxy tamper failed to map local file 2')


    def init_smarthost_server(self):
        if not path.exists(self.directory + 'Configs'):
            mkdir(self.directory + 'Configs', 755)
        self.local_rule['config.qq.com'] = {'/': self.directory + 'web' + sep}

    def parse_local_map_rule(self):
        if len(ctx.options.smarthost) < 1: return
        confs     = {}
        home      = path.expanduser('~')
        conf_file = re.sub(r'^~', home, ctx.options.smarthost)
        if path.exists(path.abspath(conf_file)):
            confs = json.loads(open(conf_file).read())
        else:
            self.log(conf_file + ' not exists')
            return;
        for _host in confs:
            items = confs[_host]
            for conf in items:
                _resp                  = re.sub(r'^~', home, conf['replace'])
                _abspath               = path.abspath(_resp) + sep
                self.local_rule[_host] = self.local_rule[_host] if _host in self.local_rule else {}
                if len(conf['request']) > 0 and path.isdir(_abspath):
                    self.local_rule[_host][conf['request']] = _abspath

    def server_smarthost(self, flow):
        method = flow.request.method
        if method == 'GET':
            info  = flow.request.path.split('?')
            if info[0] == '/': 
                flow.request.path = '/index.html' + ('?'+info[1] if len(info) == 2 else '')
            self.map_local_file(flow)
        elif method == 'POST':
            self.save_route_rules(flow)


    def save_route_rules(self, flow):
        (_form, _host, _path) = flow.request.urlencoded_form, flow.request.host, flow.request.path
        if flow.client_conn:
            (src_ip, model) = flow.client_conn.address[0].split(':')[-1], _form['proxyModel']
            (oid,    port)  = _form['oid'], _form['remotePort']
            self.remote_rule[src_ip] = {
                'model': model,
                'proxy': (_form['remoteHost'], int(port if len(port) > 0 else '8080'))
            }
            save_rule_arr = []
            for item in _form:
                (k, v) = item, _form[item]
                save_rule_arr.append(k + '=' + v)
                if k != 'proxyModel' and k != 'remoteHost' and k != 'remotePort' and k != 'oid':
                    m = re.search('^(\w+\.)+\w+$', k)
                    n = re.search('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v)
                    if m is not None and m.group and n is not None and n.group: 
                        self.remote_rule[src_ip][k] = v
            self.response_config_rule(flow)
            self.save_config_to_file(oid, '&'.join(save_rule_arr))
            self.log("\n%s's config has been set to %s.txt with config content:\n%s\n%s\n%s\n"
                % (src_ip, oid, '-'*80, '&'.join(save_rule_arr), '-'*80))

    def save_config_to_file(self, oid, config):
        oid = re.sub('[^a-z0-9]+', '', oid)
        open(self.directory + 'Configs' + sep + oid + '.txt', 'w').write(config)

    def response_config_rule(self, flow):
        (_host, _path)     = flow.request.host, flow.request.path
        header             = self.custom_header(_host, 'text/plain', 7)
        header['location'] = 'http://' + _host + _path
        _response          = HTTPResponse(b"HTTP/1.1", 200, 'ok', header, content=b'{ret:0}', is_replay=True)
        flow.response      = _response

    def map_local_file(self, flow):
        _host = flow.request.host
        if _host in self.local_rule:
            (rule, pathname) = self.local_rule[_host], flow.request.path.split("?")[0]
            for match in rule:
                if match in pathname:
                    local_file   = rule[match] + pathname.replace('/', sep).replace(match, '', 1).lstrip(sep)
                    cgi_json     = '%s.json' % local_file
                    #process hash filename like my_program_xxxxxx.js to local_file my_program_.js'
                    striped_file = re.sub(r'[a-f0-9]{6}\.(js|css|jpg|png|jpeg|gif|json)$', r'.\1', local_file)
                    if path.isfile(local_file) or path.isfile(striped_file) or path.isfile(cgi_json):
                        if path.exists(striped_file): local_file = striped_file
                        content_type  = mimetypes.guess_type(local_file)[0]
                        if content_type is None  and path.isfile(cgi_json): 
                            local_file   = cgi_json
                            content_type = 'application/json'
                        if content_type is None: break
                        body          = str(open(local_file).read()).encode('utf-8')
                        header        = self.custom_header(_host, content_type, len(body))
                        _response     = HTTPResponse(b"HTTP/1.1", 200, "local", header, body, is_replay=True)
                        flow.response = _response
                        self.log("\n%s\n%s\nReplied with Local File:\n%s\n%s\n%s\n" % (flow.request.path, '='*80, '-'*80, local_file, "-"*80))
                        break
                    elif _host == 'config.qq.com':
                        header        = self.custom_header(_host, 'text/html', 0)
                        flow.response = HTTPResponse(b"HTTP/1.1", 404, "not found", header, '', is_replay=True)
                        self.log("\n%s\n%s\nReplied with empty file%s\n" % (flow.request.path, '=' * 80, '-' * 80))
                        break
        elif DEFAULT_PROXY is not None:
            self.proxy_request_to_upstream(flow, DEFAULT_PROXY)

    def log(self, _str):
        if LOG_TO_FILE:
            _path = self.directory + 'logs' + sep
            _file = '_'.join(time.asctime().split(' ')[:3]) + '.log'
            if not path.exists(_path): mkdir(_path, 755)
            open(_path + _file, 'a+').writelines(_str + '\n')
        else:
            ctx.log.warn(_str)

    @staticmethod
    def redirect_https_to_http(flow):
        (_host, _path)     = flow.request.host, flow.request.path
        header             = Smarthost.custom_header(_host, None, 0)
        header['location'] = 'http://' + _host + _path
        _response          = HTTPResponse(b"HTTP/1.1", 302, 'redirect temporary', header, '', is_replay=True)
        flow.response      = _response

    @staticmethod
    def proxy_request_to_upstream(flow, address):
        if flow.request.method == 'CONNECT' or address is None:
            return
        if flow.request.scheme == 'http' or flow.request.scheme == 'https':
            _host  = flow.request.pretty_host if flow.request.pretty_host else flow.request.host
            _path  = flow.request.path
            _npath = (flow.request.scheme + '://' + _host + _path) if _path[0] == '/' else _path
            flow.request.headers['Connection'] = 'close'
            flow.request.path                  = _npath + ' '
            flow.live.mode                     = 'upstream'
            
            if flow.request.scheme == 'http':
                flow.live.change_upstream_proxy_server(address)
            else:
                if flow.server_conn and flow.server_conn.address:
                    ads = flow.server_conn.address
                    self.log("%s:%d --->" % (ads[0], ads[1]))
                else:
                    flow.server_conn = ServerConnectionMixin(address)
                    self.log("bad luck")
                flow.live.set_server(address, True)

    @staticmethod
    def custom_header(host, content_type, size):
        header                   = Headers(host=host)
        header['Pragma']         = 'no-store, max-age=0'
        header['Cache-Control']  = 'no-store, max-age=0'
        header["Connection"]     = "close"
        header["Server"]         = "Smarthost/1.0.0.2 for mitmproxy/2.0.2 - by mooring"
        header["Content-Length"] = str(size)
        if content_type is not None: header['Content-type'] = content_type
        return header            
        

smarthost = Smarthost()

def load(l):
    l.add_option('smarthost', str, '', 'auto reply path map')
    smarthost.parse_local_map_rule()

def request(flow):
    smarthost.flow_count += 1
    smarthost.route_proxy(flow)


def response(flow):
    cnt = smarthost.flow_count

    if cnt > FLOW_LIST_MAX_NUMBER:
        smarthost.flow_count = 0
        ctx.master.view.clear_not_marked()
    elif len(ctx.master.view):
        ctx.master.view.focus.index = len(ctx.master.view) - 1
