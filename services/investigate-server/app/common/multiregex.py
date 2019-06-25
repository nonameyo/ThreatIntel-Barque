import re
import uuid


class MultiRegex(object):
    def __init__(self):
        rules = [("^[a-f0-9]{32}$", "FILE_HASH_MD5"),
                 ("^[a-f0-9]{64}$", "FILE_HASH_SHA256"),
                 ("^[a-f0-9]{40}$", "FILE_HASH_SHA1"),
                 ("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", "DOMAIN"),
                 ("(?i)CVE-\d{4}-\d{4,7}$", "CVE"),
                 ("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", "IPv4"), ]

        merge = []
        self._messages = {}
        for regex, text in rules:
            name = "g"+str(uuid.uuid4()).replace('-', '')
            merge += ["(?P<%s>%s)" % (name, regex)]
            self._messages[name] = text

        self._re = re.compile('|'.join(merge))

    def __call__(self, s):
        result = self._re.match(s)
        if result:
            groups = result.groupdict()
            return ((self._messages[x], groups[x]) for x in groups.keys() if groups[x]).__next__()
        else:
            return ('Invalid', s)
