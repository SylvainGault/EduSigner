import base64
import binascii
import hashlib
import http.server
import json
import logging
import random
import re
import socket
import string
import subprocess
import urllib.parse

import magic
import requests



class _MySession(requests.Session):
    def __init__(self, base_url=None, **kwargs):
        super().__init__(**kwargs)
        self._base_url = base_url

    def request(self, method, url, *args, raise_=True, **kwargs):
        url = requests.compat.urljoin(self._base_url, url)
        res = super().request(method, url, *args, **kwargs)
        if raise_:
            res.raise_for_status()
        return res

    def get(self, *args, **kwargs):
        return self.request("GET", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self.request("POST", *args, **kwargs)

    def getjson(self, *args, **kwargs):
        return self.get(*args, **kwargs).json()

    def postjson(self, *args, **kwargs):
        return self.post(*args, **kwargs).json()



def _url_set_fields(url, append_query=True, **kwargs):
    """
    Replace some fields of an url, based on urllib.parse.urlparse.
    The 'query' field is handled specially as it accepts dicts, and also
    allows to add new key-value pairs instead of replacing the whole field."""

    url = urllib.parse.urlparse(url)

    if append_query:
        newquery = kwargs.pop("query", {})
        if not isinstance(newquery, dict):
            newquery = urllib.parse.parse_qs(newquery)

        kwargs["query"] = urllib.parse.parse_qs(url.query) | newquery

    # Here goes the great replacement
    url = url._replace(**kwargs)

    if isinstance(url.query, dict):
        for k, v in url.query.items():
            if isinstance(v, list) and len(v) == 1:
                url.query[k] = v[0]

        url = url._replace(query=urllib.parse.urlencode(url.query))

    return urllib.parse.urlunparse(url)



def extract_json(source, tagre):
    pos = re.search(tagre, source).end()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(source[pos:])
    return obj



class AuthHTTPDNoCodeException(Exception):
    """ Exception when the httpd didn't receive an authorization code. """

class AuthHTTPDTimeoutException(AuthHTTPDNoCodeException):
    """ Exception when the authentication timed out. """

class MSAuthenticator:
    client_id = "54e3c166-704f-4ee3-a102-618b1de5f055"
    authorize_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    discovery_url = "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1"
    scope = "openid email profile User.Read offline_access"



    def __init__(self, email=None, session=None):
        self._email = email
        self._sess = session
        if self._sess is None:
            self._sess = _MySession()

        self._port = None
        self._authurl = None


    def _build_auth_url(self, port, verifier):
        chall = hashlib.sha256(verifier.encode()).digest()
        chall = base64.urlsafe_b64encode(chall).rstrip(b"=")
        randbytes = [random.randint(0, 256) for _ in range(16)]
        randbytes[6] = (randbytes[6] | 0x40) & 0x4f
        randbytes[8] = (randbytes[8] | 0x80) & 0xbf
        reqid = "".join(f"{b:02x}" for b in randbytes)
        reqid = f"{reqid[:8]}-{reqid[8:12]}-{reqid[12:16]}-{reqid[16:20]}-{reqid[20:]}"

        params = {
            "client_id": self.client_id,
            "scope": self.scope,
            "redirect_uri": f"http://localhost:{port}/",
            "client-request-id": reqid,
            "response_mode": "query",
            "response_type": "code",
            "code_challenge": chall,
            "code_challenge_method": "S256",
            "state": 1234,
        }
        return _url_set_fields(self.authorize_url, query=params)



    def _free_port(self, host):
        """Return a port free to listen to."""
        s = socket.socket()
        s.bind((host, 0))
        port = s.getsockname()[1]
        s.close()
        return port



    def _redirect_port(self, host):
        if self._port is None:
            self._port = self._free_port(host)
        return self._port



    def _run_auth_httpd(self, port, timeout):
        """Run a simple http on the given port and return the auth code."""
        authcode = None
        received_request = False

        class MyHandler(http.server.BaseHTTPRequestHandler):
            """Handles the browser query resulting from redirect to redirect_uri."""

            def do_HEAD(self):
                """Response to a HEAD requests."""
                nonlocal received_request
                received_request = True
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

            def do_GET(self):
                """For GET request, extract code parameter from URL."""
                nonlocal authcode
                querystring = urllib.parse.urlparse(self.path).query
                querydict = urllib.parse.parse_qs(querystring)
                if "code" in querydict:
                    authcode = querydict["code"][0]
                self.do_HEAD()
                self.wfile.write(b"<html><head><title>Authorizaton result</title></head>")
                self.wfile.write(b"<body><p>Authorization redirect completed. You may "
                                 b"close this window.</p></body></html>")

        with http.server.HTTPServer(('127.0.0.1', port), MyHandler) as httpd:
            httpd.timeout = timeout
            httpd.handle_request()

        if not received_request:
            logging.warning("Authentication timeouted")
            raise AuthHTTPDTimeoutException("No request received within delay")

        if authcode is None:
            logging.warning("Form submitted without a code")
            raise AuthHTTPDNoCodeException("No code received")

        return authcode



    def _get_token_url(self):
        newquery = {"authorization_endpoint": self.authorize_url}
        disco = _url_set_fields(self.discovery_url, query=newquery)
        res = self._sess.getjson(disco)

        oidc_url = res["tenant_discovery_endpoint"]
        res = self._sess.getjson(oidc_url)
        return res["token_endpoint"]



    def _get_auth_code_browser(self):
        verifier = "".join(random.choices(string.ascii_letters, k=128))
        port = self._redirect_port("localhost")

        url = self._build_auth_url(port, verifier)
        print("Visit URL:", url)

        logging.debug("Starting browser with URL: %s", url)
        subprocess.run(["x-www-browser", url], check=False)
        return self._run_auth_httpd(port, 60 * 5), verifier



    def _get_auth_config(self, port, verifier):
        authurl = self._build_auth_url(port, verifier)
        res = self._sess.get(authurl)
        self._authurl = authurl

        cfgre = re.compile(r'\$Config\s*=\s*')
        return extract_json(res.text, cfgre)



    def _login(self, password, config):
        login_url = _url_set_fields(self._authurl, append_query=False, path=config["urlPost"], query="")
        data = {
            "login": self._email,
            "passwd": password,
            "ctx": config["sCtx"],
            "flowToken": config["sFT"],
        }
        res = self._sess.post(login_url, data=data)
        cfgre = re.compile(r'\$Config\s*=\s*')
        return extract_json(res.text, cfgre)



    def _kmsi(self, config):
        login_url = _url_set_fields(self._authurl, append_query=False, path=config["urlPost"], query="")
        data = {
            "ctx": config["sCtx"],
            "canary": config["canary"],
            "flowToken": config["sFT"],
        }
        res = self._sess.post(login_url, allow_redirects=False, data=data)
        return res.headers["Location"]



    def _get_auth_code(self, password):
        verifier = "".join(random.choices(string.ascii_letters, k=128))
        port = self._redirect_port("localhost")

        config = self._get_auth_config(port, verifier)
        config = self._login(password, config)
        location = self._kmsi(config)
        location = urllib.parse.urlparse(location)
        params = urllib.parse.parse_qs(location.query)
        return params["code"][0], verifier



    def get_token(self, password=None):
        try:
            code, verifier = self._get_auth_code(password)
        except:
            logging.info("Automated authentication failed, trying with a browser")
            code, verifier = self._get_auth_code_browser()

        logging.debug("Got auth code %r", code)

        url = self._get_token_url()
        port = self._redirect_port("localhost")

        data = {
            "client_id": self.client_id,
            "scope": self.scope,
            "redirect_uri": f"http://localhost:{port}/",
            "code": code,
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "client_info": 1,
        }
        headers = {"Origin": "https://edusign.app"}
        return self._sess.postjson(url, headers=headers, data=data)



class EduSign:
    api_url = "https://api.edusign.fr/"

    def __init__(self, login, password, method=None):
        self._sess = _MySession(base_url=self.api_url)

        if method is None or method == "plain":
            token = self._login(login, password)
        elif method.lower() == "msauth":
            token = self._msauth(login, password)
        else:
            raise ValueError(f"Unknown authentication method {method}")

        self._sess.headers["Authorization"] = f"Bearer {token}"



    def _get(self, url, *args, **kwargs):
        url = urllib.parse.urljoin(self.api_url, url)
        res = self._sess.getjson(url, *args, **kwargs)
        assert res["status"] == "success"
        return res["result"]



    def _post(self, url, *args, **kwargs):
        url = urllib.parse.urljoin(self.api_url, url)
        res = self._sess.postjson(url, *args, **kwargs)
        assert res["status"] == "success"
        return res["result"]



    def _login(self, email, password):
        creds = {"EMAIL": email, "PASSWORD": password}
        res = self._sess.postjson("/professor/account/getByCredentials", json=creds)
        assert res["status"] == "success", "Unexpected failure"
        return res["result"][0]["TOKEN"]



    def _msauth(self, email, password):
        msauth = MSAuthenticator(email)
        token = msauth.get_token(password)
        # TODO store token infos and key to refresh, maybe?
        data = {
            "accessToken": token["access_token"],
            "code": "",
            "type": "professor"
        }
        res = self._sess.postjson("/integrations/microsoft-v2/connection", json=data)
        assert res["status"] == "success"
        return res["result"][0]["TOKEN"]



    def list_accounts(self):
        return self._get("/professor/account/getByToken")



    def schools_infos(self, school_ids):
        return self._post("/professor/schools/many", json={"ids": school_ids})



    def school_info(self, school_id):
        return self._get(f"/professor/schools/{school_id}")



    def list_courses(self, school_id):
        path = f"/professor/courses/getCourses/getNextProfessorCourses/{school_id}"
        res = self._get(path)
        return res["result"]



    def course_infos(self, school_id, course_id):
        path = f"/professor/courses/{school_id}/{course_id}"
        return self._get(path)



    def sign(self, school_id, course_id, path):
        assert magic.from_file(path, mime=True) == "image/png"

        with open(path) as fp:
            sign = b"data:image/png;base64,"
            sign += bind.b2a_base64(fp.read())

        url = f"/professor/courses/setProfessorSignature/{school_id}/{course_id}"
        return self._post(url, json={"base64Signature": sign})



    def blah_sign(self):
        res = self._sess.get("https://api.edusign.fr/professor/account/getByToken")
        res.raise_for_status()
        #print(res.text)
        userinfos = res.json()["result"][0]
        schoolsid = userinfos["SCHOOL_ID"]

        res = self._sess.post("https://api.edusign.fr/professor/schools/many", json={"ids": schoolsid})
        res.raise_for_status()
        #print(res.text)

        res = self._sess.get("https://api.edusign.fr/professor/schools/" + schoolsid[-1])
        res.raise_for_status()
        #print(res.text)

        res = self._sess.get(f"https://api.edusign.fr/professor/courses/getCourses/getNextProfessorCourses/{schoolsid[-1]}/")
        res.raise_for_status()
        print(res.text)

        courses = res.json()["result"]["result"]
        course_id = courses[0]["COURSE_ID"]
        print(course_id)

        res = self._sess.get(f"https://api.edusign.fr/professor/courses/{schoolsid[-1]}/{course_id}")
        res.raise_for_status()
        print(res.text)
        return

        with open("the_end.png", "rb") as fp:
            sign = b"data:image/png;base64,"
            sign += binascii.b2a_base64(fp.read())

        res = self._sess.post(f"https://api.edusign.fr/professor/courses/setProfessorSignature/{schoolsid[-1]}/{course_id}", json={"base64Signature": sign})
        print(res)
        print(res.content)
        res.raise_for_status()
        print(res.text)
