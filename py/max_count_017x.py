from os import path
import re
import mimetypes
from mitmproxy.models import HTTPResponse, decoded
from netlib.http import Headers
C = {"MAX_FLOW_COUNT": 300, "CURRENT_COUNT": 0 }

def check_count(context, flow):
    C['CURRENT_COUNT'] += 1
    if C['CURRENT_COUNT'] >= C['MAX_FLOW_COUNT']:
        C['CURRENT_COUNT'] = 0
        #context._master.clear_events()
        context._master.clear_flows()


def request(context, flow):
    check_count(context, flow)


def response(context, flow):
    mst = context._master.state
    mst.set_focus(mst.flow_count())


def start(context, argv):
    C['CURRENT_COUNT'] = 0
