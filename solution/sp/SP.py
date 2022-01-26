import json
import typing
import uuid
from pathlib import Path
import os
import base64
import hashlib

import cherrypy
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from jinja2 import Environment, FileSystemLoader

from utils.utils import create_directory, create_get_url, asymmetric_padding_signature, asymmetric_hash

COOKIE_TTL = 200  # seconds

HOST_NAME = '127.0.0.1'
HOST_PORT = 8081
# noinspection HttpUrlsUsage
HOST_URL = f"http://{HOST_NAME}:{HOST_PORT}"

IDP_HOST_NAME = '127.0.0.1'
IDP_PORT = 8082
# noinspection HttpUrlsUsage
IDP_URL = f"http://{IDP_HOST_NAME}:{IDP_PORT}"

HELPER_HOST_NAME = "127.1.2.3"          # zkp_helper_app
HELPER_PORT = 1080
HELPER_URL = f"http://{HELPER_HOST_NAME}:{HELPER_PORT}"

clients_auth: typing.Dict[str, dict] = dict()
clients_idp: typing.Dict[str, str] = dict()

AUTH_METHODS = {
    'face': 'Face',
    'fingerprint': 'Fingerprint',
    'zkp': 'Zero Knowledge Proof (ZKP)'
}


# noinspection HttpUrlsUsage
class SP(object):
    def __init__(self):
        self.jinja_env = Environment(loader=FileSystemLoader('sp/static'))
        self.remaining_methods = []
        self.minimum_methods = 0

    def __render_page(self, page_name, **kwargs):
        return self.jinja_env.get_template(page_name).render(**kwargs)

    def __redirect_to_helper(self, methods, minimum_methods):
        __client_id = str(uuid.uuid4())
        clients_auth[__client_id] = dict()

        self.set_cookie('client_id', __client_id)

        '''Note that if you want to other IdPs you must change this piece of code to send other possible IdPs'''
        clients_idp[__client_id] = IDP_URL
        raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/login",
                                                   params={
                                                       'sp': HOST_URL,
                                                       'idp': IDP_URL,
                                                       'id_attrs': ','.join(['username']),
                                                       'consumer_url': f"{HOST_URL}/identity",
                                                       'sso_url': f"{IDP_URL}/login",
                                                       'client': __client_id,
                                                       'methods': methods,
                                                       'minimum_methods': minimum_methods,
                                                   }), 303)

    @staticmethod
    def random_name() -> str:
        """Creates a random name just for temporarility storing an uploded file
        :return:
        """
        return base64.urlsafe_b64encode(os.urandom(15)).decode('utf8')

    @staticmethod
    def set_cookie(name: str, value: str):
        """Create a session cookie (insecure, can be forged)
        The validity is short by design, to force authentications
        :param value:
        :param name:
        :return:
        """
        cookie = cherrypy.response.cookie
        cookie[name] = value
        cookie[name]['path'] = '/'
        cookie[name]['max-age'] = f"{COOKIE_TTL}"
        cookie[name]['version'] = '1'

    def account_contents(self, account: str) -> str:
        """Present the account images and an upload form
        :param account:
        :return:
        """
        contents = '<html><body>'
        contents += '<p>Upload a new image file</p>'
        contents += '<form action="add" method="post" enctype="multipart/form-data">'
        contents += '<input type="file" name="image" /><br>'
        contents += '<input type="submit" value="send" />'
        contents += '</form>'
        contents += '<form action="add" method="post" enctype="multipart/form-data">'
        contents += '<p>List of uploaded image file</sp>'
        contents += '<table border=0><tr>'

        path = f"accounts/{account}"
        files = os.listdir(path)
        count = 0
        images_src = []
        for f in files:
            contents += '<td><img src="/img?name=' + f + '"></td>'
            count += 1
            if count % 4 == 0:
                contents += '</tr><tr>'
            images_src.append(f"/img?name={f}")
        contents += '</tr></body></html>'
        return self.__render_page('account_contents.html', images=images_src)
        # return contents

    @staticmethod
    def prepare_auth_parameter(request):
        return {
            'http_host': request.local.name,
            'script_name': request.path_info,
            'server_port': request.local.port,
            'get_data': request.params.copy(),
            'post_data': request.params.copy()
        }

    def get_account(self, redirect):
        """Checks if the request comes with an account cookie
        This code is unsafe (the cookie can be forged!)
        :param redirect:
        :return:
        """

        cookies = cherrypy.request.cookie
        # if not cookies:
        if 'client_id' not in cookies:
            if redirect:
                raise cherrypy.HTTPRedirect('/auth_methods', status=307)
            else:
                return False

        client_id = cookies['client_id'].value
        if client_id not in clients_auth or not clients_auth[client_id]:
            if redirect:
                raise cherrypy.HTTPRedirect('/auth_methods', status=307)
            else:
                return False

        username = clients_auth[client_id]['username']
        self.set_cookie('client_id', client_id)  # for keeping the session alive
        return username

    @cherrypy.expose
    def index(self):
        """Root HTTP server method
        :return:
        """
        account = self.get_account(True)

        create_directory('accounts')
        create_directory(f"accounts/{account}")

        raise cherrypy.HTTPRedirect('/account', status=307)

    @cherrypy.expose
    def auth_methods(self, **kwargs):
        if cherrypy.request.method == 'GET':
            return self.__render_page('index_auth.html', methods=AUTH_METHODS)
        elif cherrypy.request.method == 'POST':
            if 'methods' not in kwargs:
                return self.__render_page('index_auth.html', methods=AUTH_METHODS,
                                          message="Error: You must select at least one method!")
            elif 'minimum' not in kwargs:
                return self.__render_page('index_auth.html', methods=AUTH_METHODS,
                                          message="Error: You must select the number of biometric methods to consider!")

            if type(kwargs['methods']) is str:
                kwargs['methods'] = list(kwargs['methods'])

            # verifications
            for method in kwargs['methods']:
                if method not in AUTH_METHODS:
                    self.__render_page('index_auth.html', methods=AUTH_METHODS,
                                       message="Error: You must select a valid method!")

            if not kwargs['minimum'].isnumeric() or int(kwargs['minimum']) > len(AUTH_METHODS):
                self.__render_page('index_auth.html', methods=AUTH_METHODS,
                                   message="You must select a valid minimum of methods!")

            self.remaining_methods = kwargs['methods'][1:]
            self.minimum_methods = int(kwargs['minimum'])

            self.__redirect_to_helper(methods=base64.urlsafe_b64encode(json.dumps(kwargs['methods']).encode()),
                                      minimum_methods=int(kwargs['minimum']))
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def login(self) -> str:
        """Login page, which performs a (visible) HTML redirection
        :return:
        """
        return self.__render_page('login.html')

    @cherrypy.expose
    def identity(self, response, methods_successful, methods_unsuccessful, signature, client):
        """Identity provisioning by an IdP
        :param client:
        :param response:
        :param signature:
        :return:
        """
        if cherrypy.request.method == 'POST':
            signature = base64.urlsafe_b64decode(signature)

            try:
                # read from the file where is stored the used IdP (the file name will be the base64 of the IdP's URL)
                file_name = base64.urlsafe_b64encode(clients_idp[client].encode()).decode()
                with open(f'sp/idps_certificates/{file_name}.crt', 'rb') as file:
                    cert_data = file.read()
                cert = x509.load_pem_x509_certificate(data=cert_data, backend=default_backend())
                cert.public_key().verify(signature=signature, data=response.encode(),
                                         padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())
            except InvalidSignature:
                del clients_auth[client]
                return "<h1>Error: Invalid signature from the Identity Provider!</h1>"
            except Exception as e:
                del clients_auth[client]
                print(f"Error in function <{self.identity.__name__}>: <{e}>")
                return

            attributes = json.loads(base64.urlsafe_b64decode(response))
            methods_successful = json.loads(base64.urlsafe_b64decode(methods_successful))
            methods_unsuccessful = json.loads(base64.urlsafe_b64decode(methods_unsuccessful))

            print(f"attributes: {attributes}")
            print(f"Methods successful: {methods_successful}")
            print(f"Methods unsuccessful: {methods_unsuccessful}")

            cookies = cherrypy.request.cookie
            request_id = cookies['client_id'].value
            clients_auth[request_id] = attributes

        return self.__render_page('redirect_index.html')

    @cherrypy.expose
    def account(self) -> str:
        """Expose account page
        :return:
        """
        account = self.get_account(True)
        return self.account_contents(account)

    @cherrypy.expose
    def img(self, name: str):
        """Get individual account image
        :param name:
        :return:
        """
        account = self.get_account(True)
        path = f"{os.getcwd()}/accounts/{account}/{name}"
        return cherrypy.lib.static.serve_file(path, content_type='jpg')

    @cherrypy.expose
    def add(self, image):
        """Upload new image for an account
        :param image:
        :return:
        """
        name = self.random_name()
        account = self.get_account(False)
        if not account:
            return self.__render_page('login.html')

        path = Path(f"{os.getcwd()}/accounts/{account}/{name}")
        m = hashlib.sha1()
        with path.open('wb') as new_file:
            while True:
                data = image.file.read(8192)
                if not data:
                    break
                new_file.write(data)
                m.update(data)

        name = base64.urlsafe_b64encode(m.digest()[0:18]).decode('utf8')
        new_path = Path(f"{os.getcwd()}/accounts/{account}/{name}")
        if not new_path.exists():
            path.rename(new_path)
        else:
            path.unlink(missing_ok=True)

        return self.account_contents(account)


if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host': HOST_NAME,
                            'server.socket_port': HOST_PORT})
    cherrypy.quickstart(SP())
