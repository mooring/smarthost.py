from os import path
import re
import mimetypes
from mitmproxy.models import HTTPResponse, decoded
from netlib.http import Headers
from mitmproxy import ctx
C = {"MAX_FLOW_COUNT": 300, "CURRENT_COUNT": 0 }

def request(flow):
    C['CURRENT_COUNT'] += 1
    if C['CURRENT_COUNT'] >= C['MAX_FLOW_COUNT']:
        C['CURRENT_COUNT'] = 0
        ctx.master.state.clear()

def response(flow):
    ctx.master.state.set_focus(C['CURRENT_COUNT'])


def start():
    C['CURRENT_COUNT'] = 0
