import os
import sys
import json
import inspect

from collections import OrderedDict

from burp import IBurpExtender, IParameter, IScanIssue
from burp import IContextMenuFactory, IContextMenuInvocation

import thread
from javax.swing import JMenuItem

# Import blackboxprotobuf
_BASE_DIR = os.path.abspath(os.path.dirname(inspect.getfile(inspect.currentframe())))

sys.path.insert(0, _BASE_DIR + "/blackboxprotobuf/lib/")
sys.path.insert(0, _BASE_DIR + "/blackboxprotobuf/burp/deps/six/")
sys.path.insert(0, _BASE_DIR + "/blackboxprotobuf/burp/deps/protobuf/python/")

# Hack to fix loading protobuf libraries within Jython. See https://github.com/protocolbuffers/protobuf/issues/7776
def fix_protobuf():
    import six

    u = six.u

    def new_u(s):
        if s == r"[\ud800-\udfff]":
            # Don't match anything
            return "$^"
        else:
            return u(s)

    six.u = new_u

fix_protobuf()

import blackboxprotobuf
import parse_proto


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.helpers = callbacks.getHelpers()
        self.callbacks = callbacks

        callbacks.setExtensionName("BlackboxProtobuf x Youtube")
        callbacks.registerContextMenuFactory(self)


    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        messages = invocation.getSelectedMessages()

        if (context in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                       IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
                       IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
                       IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
                       IContextMenuInvocation.CONTEXT_PROXY_HISTORY] and len(messages) == 1):

            label = "Send 'alt=json' request"
            if messages[0].getResponse():
                menuItem = JMenuItem(label, actionPerformed=self.sendAltJsonRequest)
                menuItem.putClientProperty('httpRequestResponse', messages[0])
                return [menuItem]

    def sendAltJsonRequest(self, event):
        menuItem = event.getSource()
        httpRequestResponse = menuItem.getClientProperty('httpRequestResponse')

        httpRequest = httpRequestResponse.getRequest()

        altParameter = self.helpers.buildParameter("alt", "json", IParameter.PARAM_URL)
        httpRequest = self.helpers.updateParameter(httpRequest, altParameter)

        thread.start_new_thread(self.sendHttpRequestAndStore, (httpRequestResponse, httpRequest))

    def sendHttpRequestAndStore(self, originalHttpRequestResponse, httpRequest):
        httpService = originalHttpRequestResponse.getHttpService()
        originalHttpResponse = originalHttpRequestResponse.getResponse()

        httpRequestResponse = self.callbacks.makeHttpRequest(httpService, httpRequest)

        analyzedOriginalResponse = self.helpers.analyzeResponse(originalHttpResponse)
        analyzedResponse = self.helpers.analyzeResponse(httpRequestResponse.getResponse())
        if (analyzedResponse.getInferredMimeType() != "JSON"
                or analyzedOriginalResponse.getStatusCode() != analyzedResponse.getStatusCode()):
            self.callbacks.issueAlert('Invalid response received (from sendHttpRequestAndStore)\n%s' %
                                      self.helpers.bytesToString(httpRequestResponse.getResponse()))
            raise Exception('Invalid response! Check Event logs...')

        responseProtoRaw = originalHttpResponse[analyzedOriginalResponse.getBodyOffset():].tostring()

        httpResponse = httpRequestResponse.getResponse()
        responseJson = json.loads(httpResponse[analyzedResponse.getBodyOffset():].tostring(),
                                  object_pairs_hook=OrderedDict)

        proto_json, proto_typedef = blackboxprotobuf.protobuf_to_json(responseProtoRaw)
        parse_proto.map_verbose_keys(responseJson, proto_typedef)

        url = self.helpers.analyzeRequest(httpService, httpRequest).getUrl()
        path = url.getPath()

        if path.endswith("/"):
            path = path[:-1]

        segment = path.split("/")[-1]
        message = json.dumps(proto_typedef)

        try:
            originalHttpRequestResponse.setComment("TypeDef:\n" + message)
        except:
            # Fix for 'Item does not support comments'
            pass

        issue = ProtobufIssue(
            httpService=httpService,
            url=url,
            originalRequestResponse=originalHttpRequestResponse,
            newRequestResponse=httpRequestResponse,
            name="Protobuf/JSON mapping from 'alt=json' request: " + segment,
            detail="Add <strong>" + segment + "</strong> Type Definition:<br/><br/>" + message,
        )

        self.callbacks.addScanIssue(issue)


class ProtobufIssue(IScanIssue):
    def __init__(self, httpService, url, originalRequestResponse, newRequestResponse, name, detail):
        self._httpService = httpService
        self._url = url
        self._originalRequestResponse = originalRequestResponse
        self._newRequestResponse = newRequestResponse
        self._name = name
        self._detail = detail

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return [self._originalRequestResponse, self._newRequestResponse]

    def getHttpService(self):
        return self._httpService

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Open the `Response` tab > `Protobuf` > Edit or Add new type"

    def getIssueDetail(self):
        return self._detail

    def getRemediationBackground(self):
        return None

    def getRemediationDetail(self):
        return None