#Usage  : -s "map_local.py host1=path1,local1_path#path2,local2 host2=path3,local3"
#Example: mitmproxy -s "smarthost.py qq.com=/js/,./js#/css/,./css" --port 8080
#Author : mooring 2015/08/10

from os import path, mkdir, sep, getcwd
import re, mimetypes
from mitmproxy.models import HTTPResponse, decoded
from netlib.http import Headers

#mac/*nix path
WORK_PATH     =  '/Users/mooring/.mitmproxy/web/'
#DEFAULT_PROXY = None   #if not in proxy env, set this to None
DEFAULT_PROXY = None
if sep!='/': WORK_PATH = getcwd() + sep + 'web' + sep

class Smarthost:
    def __init__(self):
         self.local_rule   = {}
         self.remote_rule  = {}

    def route_proxy(self, context, flow):
        host, src_ip = flow.request.host, None
        if flow.client_conn:
            src_ip = flow.client_conn.address.host
        if host == 'config.qq.com' or host == 'smart.host':
            self.server_smarthost(context, flow, src_ip)
        elif flow.request.scheme == 'https' and (host in  self.local_rule or src_ip in self.remote_rule):
            self.redirect_https_to_http(context, flow)
        else:
            if src_ip is not None:
                if src_ip in self.remote_rule:
                    self.remote_proxy_tamper(context, flow, src_ip)
                else:
                    self.map_local_file(context, flow)
            else:
                self.map_local_file(context, flow)

    def server_smarthost(self, context, flow, src_ip):
        method, host = flow.request.method, flow.request.host
        if method == 'GET':
            info = flow.request.path.split('?')
            if info[0] == '/': flow.request.path = '/index.html?' + (info[1] if len(info)==2 else '')
            self.map_local_file(context, flow)
        elif method == 'POST':
            self.save_route_rules(context, flow)
        else:
            pass

    def save_route_rules(self, context, flow):
        form, host, path = flow.request.urlencoded_form, flow.request.host, flow.request.path
        if flow.client_conn:
            src_ip, model, oid, port = flow.client_conn.address.host, form['proxyModel'][0], form['oid'][0], form['remotePort'][0]
            self.remote_rule[src_ip] = {
                'model': model,
                'proxy': (form['remoteHost'][0], int(port if len(port)>0 else '8080'))
            }
            save_rule_arr = []
            for item in form:
                k, v = item[0], item[1]
                save_rule_arr.append(k + '=' + v)
                if k == 'proxyModel' or k == 'remoteHost' or k == 'remotePort' or k == 'oid':
                    pass
                else:
                    m = re.search('^(\w+\.)+\w+$', k)
                    n = re.search('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v)
                    if m is not None and m.group and n is not None and n.group:
                        self.remote_rule[src_ip][k] = v
            self.response_config_rule(context, flow)
            self.save_config_to_file(oid, '&'.join(save_rule_arr) )
            context.log("\n%s's config has been set to %s.txt with config content:\n%s\n%s\n%s\n"
                % (src_ip, oid, '-'*80, '&'.join(save_rule_arr), '-'*80) )

    def save_host_pair_to_index(self, context, flow):
        pass

    def save_config_to_file(self, oid, config):
        oid = re.sub('[^a-z0-9]+','',oid)
        open(WORK_PATH.rstrip(sep) + sep + 'Configs' + sep + oid + '.txt', 'w').write(config)
        pass

    def response_config_rule(self, context, flow):
        host, path    = flow.request.host, flow.request.path
        h             = self.custom_header(host, 'text/plain', '7')
        h['location'] = 'http://' + host + path
        response = HTTPResponse(http_version=b"HTTP/1.1", status_code=200, reason='ok', headers=h, content= '{ret:0}')
        response.is_replay = True
        flow.reply(response)

    def redirect_https_to_http(self, context, flow):
        host, path = flow.request.host, flow.request.path
        h = self.custom_header(host, None, '0')
        h['location'] = 'http://' + host + path
        response = HTTPResponse(http_version=b"HTTP/1.1", status_code=302, reason='redirect', headers=h, content= '')
        response.is_replay = True
        flow.reply(response)

    def proxy_request_to_upstream(self, context, flow, address):
        if flow.request.scheme == 'http' or flow.request.scheme == 'https':
            host  = flow.request.pretty_host if flow.request.pretty_host else flow.request.host
            path  = flow.request.path
            npath = (flow.request.scheme + '://' + host + path) if path[0] == '/' else path
            flow.request.headers['Connection'] = 'close'
            flow.request.path = npath + ' '; flow.live.mode = 'upstream'
            if flow.request.scheme == 'http':
                flow.live.change_upstream_proxy_server(address)
            else:
                flow.live.set_server(address, True)

    def remote_proxy_tamper(self, context, flow, src_ip):
        if flow.live and flow.request.method != 'CONNECT':
            host, cur_rule, pathname = flow.request.host, self.remote_rule[src_ip], flow.request.path
            if cur_rule['model'] == 'local' and host in cur_rule and len(cur_rule[host])>0:
                self.proxy_request_to_upstream(context, flow, address,(cur_rule[host], 80))
                context.log('request %s has been hosted to %s with query path\n%s\n%s\n%s\n'
                    % (host, cur_rule[host], '-'*80, pathname, '-'*80))
            elif cur_rule['model'] == 'remote' and cur_rule['proxy']:
                self.proxy_request_to_upstream(context, flow, cur_rule['proxy'])
                context.log('request %s has been proxied to %s width port %d with query path\n%s\n%s\n%s\n'
                    % (host, cur_rule['proxy'][0], cur_rule['proxy'][1], '-'*80, pathname,'-'*80 ) )
            else:
                context.log('what a fuck')
                pass
        else:
            context.log('are you kidding me ?')
            pass

    def map_local_file(self, context, flow):
        host = flow.request.host
        if host in  self.local_rule:
            rule, pathname =  self.local_rule[host], flow.request.path.split("?")[0]
            for match in rule:
                if match in pathname:
                    form = flow.request.urlencoded_form
                    local_file = rule[match] + pathname.replace('/',sep).replace(match, '', 1).lstrip(sep)
                    striped_file = re.sub(r'[a-f0-9]{6}\.(js|css|jpg|png|jpeg|gif)$', r'.\1', local_file)
                    if path.isfile(local_file) or path.isfile(striped_file):
                        if path.exists(striped_file): local_file = striped_file
                        content_type = mimetypes.guess_type(local_file)[0]
                        if content_type[0] is None: break
                        body = str(open(local_file).read())
                        h = self.custom_header(host, content_type, str(len(body)))
                        response = HTTPResponse(http_version=b"HTTP/1.1", status_code=200, reason="local", headers=h, content=body)
                        response.is_replay = True
                        flow.response = response
                        context.log("\n%s\n%s\nReplied with Local File:\n%s\n%s\n%s\n" % (flow.request.path, '-'*60, '-' * 80, local_file, "-" * 80))
                        break
        else:
            if flow.live and DEFAULT_PROXY is not None:
                self.proxy_request_to_upstream(context, flow, DEFAULT_PROXY)

    def custom_header(self, host, content_type, size):
        header = Headers(host=host)
        header['Max-Age'] = '0'
        header['Cache-Control'] = 'no-store'
        header["Connection"] = "close"
        header["Server"] = "mitmproxy map local plugin by mooring/0.0.1.4"
        header["Content_Length"] = size
        if content_type is not None:
            header['Content-type'] = content_type
        return header

    def init_smarthost_server(self, context, argv):
        smarthost_config = {}
        smarthost_config['/'] = WORK_PATH
        if not path.exists(WORK_PATH.rstrip(sep) + sep + 'Configs'):
            mkdir(WORK_PATH.rstrip(sep) + sep + 'Configs', 0x600)
        self.local_rule['config.qq.com'] = smarthost_config
        self.local_rule['smart.host'] = smarthost_config

    def config_smarthost(self, context, flow):
        pass

    def show_svr_host(self, context, flow):
        if flow.server_conn:
            dst_ip = flow.server_conn.peer_address.host
            flow.request.headers['Server-Address']  = dst_ip

    def parse_local_map_rule(self, context, argv):
        if len(argv) < 2: return
        for k in range(1, len(argv)):
            rule = argv[k].split('=')
            if len(rule) == 2 and len(rule[0]) > 0 and len(rule[1]) > 0:
                pair, host = None, rule[0],
                if len(host) > 0:
                    self.local_rule[host], matches = {}, rule[1].split('#')
                    for j in matches:
                        pair = j.split(',')
                        if len(pair) != 2: continue
                        abspath = path.abspath(pair[1]) + sep
                        if len(pair[0]) > 0 and len(pair[1]) > 0 and path.isdir(abspath):
                            self.local_rule[host][pair[0]] = abspath

smarthost = Smarthost()
def start(context, argv):
    smarthost.init_smarthost_server(context, argv)
    smarthost.parse_local_map_rule(context, argv)

#def tcp_message(context, tcp_msg):
#    pass

#def clientconnect(context, root_layer):
#    context.log("client cennect root_layer")
#    pass

def request(context, flow):
    smarthost.show_svr_host(context, flow)
    smarthost.route_proxy(context, flow)
    mst = context._master.state
    mst.set_focus(mst.flow_count())

def response(context, flow):
    smarthost.config_smarthost(context, flow)

#def clientdisconnect(context, root_layer):
#    context.log("client disconnect root_layer")
#    context.log(root_layer)

def error(context, flow):
    pass
