import json
import falcon
from uuid import uuid4
from datetime import datetime


class Middelware(object):
    def __init__(self):
        super(Middelware, self).__init__()
        self._excluded_resources = ('/ping')

    def process_request(self, req: falcon.Request, _: falcon.Response) -> None:
        if req.path not in self._excluded_resources:
            req.context['received_at'] = datetime.now()
            req.context['remote_addr'] = req.remote_addr
            req.context['access_route'] = req.access_route
            req.context['user_agent'] = req.user_agent
            req.context['body'] = {}
            if req.content_length:
                req.context['body'] = json.load(req.bounded_stream)

    def process_response(self, req, resp, resource, req_succeeded):
        resp.set_header('Access-Control-Allow-Origin', '*')

        if (req_succeeded and req.method == 'OPTIONS'
                and req.get_header('Access-Control-Request-Method')):
            allow = resp.get_header('Allow')
            resp.delete_header('Allow')

            allow_headers = req.get_header(
                'Access-Control-Request-Headers', default='*')

            resp.set_headers((
                ('Access-Control-Allow-Methods', allow),
                ('Access-Control-Allow-Headers', allow_headers),
                ('Access-Control-Max-Age', '86400'),  # 24 hours
            ))
