from http.client import HTTPResponse
from io import BytesIO
# https://stackoverflow.com/questions/24728088/python-parse-http-response-string
http_response_str = """HTTP/1.0 302 Found\u000d\u000aLocation: https:///\u000d\u000aServer: BigIP\u000d\u000aConnection: close\u000d\u000aContent-Length: 0\u000d\u000a\u000d"""

http_response_bytes = http_response_str.encode()


class FakeSocket():
  def __init__(self, response_bytes):
      self._file = BytesIO(response_bytes)

  def makefile(self, *args, **kwargs):
      return self._file


source = FakeSocket(http_response_bytes)
response = HTTPResponse(source)
response.begin()
print("status:", response.status)
# status: 200
print("single header:", response.headers.items())
# single header: text/xml; charset="utf-8"
print("content:", response.read(len(http_response_str)))
# content: b'teststring'
