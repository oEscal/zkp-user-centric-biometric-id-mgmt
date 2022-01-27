import base64
import json
import random
from queue import Queue

import cherrypy
import requests
from ws4py.server.cherrypyserver import WebSocketPlugin, WebSocketTool
from ws4py.websocket import WebSocket

from helper.biometric_systems.facial.facial_recognition import Face_biometry
from helper.biometric_systems.fingerprint.fingerprint import Fingerprint, IMAGE_DATA, VALID_IMAGE, ALL_IMAGES_VALID, \
    FINGERPRINT_ERRORS
from utils.utils import ZKP, overlap_intervals, \
    Cipher_Authentication, asymmetric_upload_derivation_key, create_get_url
from helper.managers import Master_Password_Manager, Password_Manager
from jinja2 import Environment, FileSystemLoader

MIN_ITERATIONS_ALLOWED = 200
MAX_ITERATIONS_ALLOWED = 500

NUMBER_FACES_REGISTER = 14

HELPER_HOST_NAME = "127.1.2.3"  # zkp_helper_app
HELPER_PORT = 1080
HELPER_URL = f"http://{HELPER_HOST_NAME}:{HELPER_PORT}"
HELPER_URL_WS = f"ws://{HELPER_HOST_NAME}:{HELPER_PORT}"

ws_queue = Queue()


class WebSocketHandler(WebSocket):
    def received_message(self, m):
        ws_queue.put(str(m))

    def closed(self, code, reason="A client left the room without a proper explanation."):
        ws_queue.put("closed")


class HelperApp(object):
    def __init__(self):
        self.zkp: ZKP = None

        self.iterations = 0

        self.idp = ''
        self.sp = ''
        self.id_attrs = []
        self.consumer_url = ''
        self.sso_url = ''
        self.auth_url = ''
        self.save_pk_url = ''
        self.id_url = ''
        self.auth_bio = ''
        self.reg_bio = ''

        self.idp_client = ''
        self.sp_client = ''

        self.cipher_auth: Cipher_Authentication = None
        self.password_manager: Password_Manager = None
        self.master_password_manager: Master_Password_Manager = None

        self.username = ''

        self.max_idp_iterations = 0
        self.min_idp_iterations = 0

        self.response_attrs_b64 = ''
        self.response_signature_b64 = ''
        self.methods_successful_b64 = ''
        self.methods_unsuccessful_b64 = ''

        self.jinja_env = Environment(loader=FileSystemLoader('helper/static'))
        self.face_biometry: Face_biometry = None  # = Face_biometry('escaleira')
        self.fingerprint: Fingerprint = None
        self.register_biometric = False
        self.registration_method = ''

        self.message = ""

    @staticmethod
    def static_contents(path):
        return open(f"helper/static/{path}", 'r').read()

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect('/register')

    @cherrypy.expose
    def error(self, error_id: str):
        errors = {
            'asymmetric_challenge': "The response to the challenge sent to the IdP to authentication with "
                                    "asymmetric keys is not valid. A possible cause for this is the IdP we "
                                    "are contacting is not a trusted one!",
            'zkp_idp_error': "Received error from IdP!",
            'idp_iterations': "The range of allowed iterations received from the IdP is incompatible with the range "
                              "allowed by the local app. A possible cause for this is the IdP we are contacting is not "
                              "a trusted one!"
                              "<br>"
                              "You can access the page '<a href=\"/choose_iterations\">/choose_iterations</a>' to "
                              "choose the number of iterations manually.",
            'zkp_auth_error': "There was an error on ZKP authentication. This could mean that or the introduced "
                              "password or username are incorrect, or the IdP we are contacting is not a trusted one!"
                              "<br>"
                              "You can access the page '<a href=\"/update_idp_user\">/update_idp_user</a>' to update "
                              "this user's credentials.",
            'load_pass_error': "There was an error on loading the selected user credentials. Access the page "
                               "'<a href=\"/update_idp_user\">/update_idp_user</a>' to update this user's "
                               "local credentials.",
            'zkp_save_keys': "There was an error on IdP saving the public keys. This could mean that there was an "
                             "unexpected error on the ZKP protocol!",
            'zkp_inf_cycle': "The ZKP was already executed one time previously, which means that there was some error "
                             "on the identification process!",
            'asy_error_decrypt': "There was an error decrypting the data received from the IdP. A possible cause for "
                                 "this is the IdP we are contacting is not a trusted one!",
        }
        return self.__render_page('error.html', message=errors[error_id])

    @cherrypy.expose
    def login(self, sp: str, idp: str, id_attrs: str, consumer_url: str, sso_url: str, client: str, methods: str,
              minimum_methods: str):
        self.__init__()
        attrs = id_attrs.split(',')
        return self.__render_page('login_attributes.html', sp=sp, idp=idp, id_attrs=attrs,
                                  sso_url=sso_url, consumer_url=consumer_url,
                                  client=client, methods=methods, minimum_methods=minimum_methods)

    def __is_logged_in(self):
        return bool(self.master_password_manager)

    def __can_add_idp_user(self):
        return self.__is_logged_in() and len(self.master_password_manager.idps) > 0

    def __render_page(self, page_name, **kwargs):
        return self.jinja_env.get_template(page_name).render(**kwargs, logout=self.__is_logged_in(),
                                                             add_idp_user=self.__can_add_idp_user())

    @cherrypy.expose
    def logout(self):
        self.master_password_manager = None
        raise cherrypy.HTTPRedirect('/register', status=303)

    @cherrypy.expose
    def authorize_attr_request(self, sp: str, idp: str, id_attrs: list, consumer_url: str, sso_url: str, client: str,
                               methods: str, minimum_methods: str, **kwargs):
        if 'deny' in kwargs:
            return self.__render_page('auth_refused.html')
        elif 'allow' in kwargs:
            self.sp = sp
            self.idp = idp
            self.id_attrs = [e for e in id_attrs if e]
            self.consumer_url = consumer_url
            self.sso_url = sso_url
            self.sp_client = client

            raise cherrypy.HTTPRedirect(create_get_url(self.sso_url, params={
                'methods': methods, 'minimum_methods': minimum_methods}), status=303)

    def asymmetric_identification(self):
        id_attrs_b64 = base64.urlsafe_b64encode(json.dumps(self.id_attrs).encode())
        id_attrs_signature_b64 = base64.urlsafe_b64encode(self.password_manager.sign(id_attrs_b64))

        ciphered_params = self.cipher_auth.create_response({
            'user_id': self.password_manager.user_id,
            'id_attrs': id_attrs_b64.decode(),
            'signature': id_attrs_signature_b64.decode(),
            'username': self.password_manager.idp_username
        })
        response = requests.get(self.id_url,
                                params={
                                    'client': self.idp_client,
                                    **ciphered_params
                                })
        if response.status_code != 200 and response.status_code != 401:
            print(f"Error status: {response.status_code}")
            self.zkp_auth()
        else:
            response_dict = self.cipher_auth.decipher_response(response.json())
            if response_dict['redirect']:
                raise cherrypy.HTTPRedirect(response_dict['url'], status=response_dict['status_code'])

            try:
                aes_key = self.password_manager.decrypt(base64.urlsafe_b64decode(response_dict['ciphered_aes_key']))
            except Exception as e:
                print(f"Error in function <{self.asymmetric_identification.__name__}>: <{e}>")
                raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/error",
                                                           params={'error_id': 'asy_error_decrypt'}), 301)

            iv = base64.urlsafe_b64decode(response_dict['iv'])
            new_cipher = Cipher_Authentication(aes_key)

            response_dict_attrs = new_cipher.decipher_data(
                data=response_dict['response'],
                iv=iv
            )

            if response.status_code == 200:
                self.response_attrs_b64 = response_dict['response']
                self.response_signature_b64 = response_dict['signature']

            self.methods_successful_b64 = base64.urlsafe_b64encode(
                json.dumps(response_dict['methods_successful']).encode()).decode()
            self.methods_unsuccessful_b64 = base64.urlsafe_b64encode(
                json.dumps(response_dict['methods_unsuccessful']).encode()).decode()

        raise cherrypy.HTTPRedirect("/attribute_presentation", 303)

    def zkp_auth(self, restart=False):
        # verify if zkp was already done previously
        # if not restart and self.zkp is not None:
        #     raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/error",
        #                                                params={'error_id': 'zkp_inf_cycle'}), 301)

        self.zkp = ZKP(self.password_manager.password)
        data_send = {
            'nonce': '',
        }
        for i in range(self.iterations):
            if i == 0 and restart:
                data_send['restart'] = restart
            else:
                data_send['restart'] = False

            data_send['nonce'] = self.zkp.create_challenge()
            ciphered_params = self.cipher_auth.create_response({
                **data_send,
                **({
                       'username': self.password_manager.idp_username,
                       'iterations': self.iterations
                   } if self.zkp.iteration < 2 else {})
            })
            response = requests.get(self.auth_url, params={
                'client': self.idp_client,
                **ciphered_params
            })

            if response.status_code == 200:
                # verify if response to challenge is correct
                response_dict = self.cipher_auth.decipher_response(response.json())
                idp_response = int(response_dict['response'])
                self.zkp.verify_challenge_response(idp_response)

                # create both response to the IdP challenge and new challenge to the IdP
                challenge = response_dict['nonce'].encode()
                challenge_response = self.zkp.response(challenge)
                data_send['response'] = challenge_response
            else:
                print(f"Error received from idp: <{response.status_code}: {response.reason}>")
                raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/error",
                                                           params={'error_id': 'zkp_idp_error'}), 301)

        if self.zkp.all_ok:
            # save the password locally
            self.password_manager.save_password()

            # create asymmetric credentials
            key = asymmetric_upload_derivation_key(self.zkp.responses, self.zkp.iteration, 32)
            asymmetric_cipher_auth = Cipher_Authentication(key=key)

            # generate asymmetric keys
            self.password_manager.generate_keys()
            response = requests.post(self.save_pk_url, data={
                'client': self.idp_client,
                **self.cipher_auth.create_response(asymmetric_cipher_auth.create_response({
                    'key': self.password_manager.get_public_key_str()
                }))
            })

            if response.status_code != 200:
                print(f"Error received from idp: <{response.status_code}: {response.reason}>")
                raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/error",
                                                           params={'error_id': 'zkp_save_keys'}), 301)

            response = asymmetric_cipher_auth.decipher_response(self.cipher_auth.decipher_response(response.json()))
            if 'status' in response and bool(response['status']):
                self.password_manager.save_private_key(user_id=response['user_id'], time_to_live=float(response['ttl']))
        else:
            self.message = "There was an error on ZKP authentication. This could mean that or the introduced " \
                           "password or username are incorrect, or the IdP we are contacting is not a trusted one!" \
                           "<br>" \
                           "You can access the page '<a href=\"/update_idp_user\">/update_idp_user</a>' to update " \
                           "this user's credentials."
            raise cherrypy.HTTPRedirect("/attribute_presentation", 303)

        # if the authentication is done for the registration with biometrics, redirect
        if self.register_biometric:
            self.__biometric_registration_final()
        else:
            # in the end, we request the attributes with the new key pair
            self.asymmetric_identification()

    @cherrypy.expose
    def keychain(self, username: str, password: str, action: str = 'auth'):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        password = password.encode()

        # verify master password
        self.master_password_manager = Master_Password_Manager(username=username, master_password=password)
        if not self.master_password_manager.login():
            self.master_password_manager = None
            return self.__render_page('keychain.html', action=action, message='Error: Unsuccessful login!')

        if action == 'auth':
            return self.__render_page('select_idp_user.html', idp=self.idp,
                                      users=self.master_password_manager.get_users_for_idp(self.idp),
                                      submit=len(self.username) > 0, username=self.username)
        elif action == 'update':
            return self.__render_page('update.html')
        elif action == 'update_idp':
            raise cherrypy.HTTPRedirect("/update_idp_credentials", 301)
        elif action == 'biometric_register':
            raise cherrypy.HTTPRedirect("/biometric_register", 301)
        else:
            raise cherrypy.HTTPError(401)

    @cherrypy.expose
    def select_idp_user(self, idp_user: str = ''):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        if not idp_user or idp_user not in self.master_password_manager.get_users_for_idp(self.idp):
            raise cherrypy.HTTPError(401)

        self.username = idp_user

        master_username = self.master_password_manager.username
        master_password = self.master_password_manager.master_password
        self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                 idp_user=idp_user, idp=self.idp)

        if not self.password_manager.load_password():
            raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/error",
                                                       params={'error_id': 'load_pass_error'}), 301)
        else:
            if not self.password_manager.load_private_key():
                self.zkp_auth()
            else:
                self.asymmetric_identification()

    @cherrypy.expose
    def add_idp_user(self, username='', password='', idp='', referer=None):
        if cherrypy.request.method == 'GET':
            return self.__render_page('add_idp_user.html', idps=self.master_password_manager.idps)

        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        if not username or not password or not idp:
            return self.__render_page("select_idp_user.html", idp=idp,
                                      users=self.master_password_manager.get_users_for_idp(idp),
                                      message='Error: You must enter a new username with a password and the IDP!')

        # update keychain registered idp users
        if not self.master_password_manager.add_idp_user(idp_user=username, idp=idp):
            return self.__render_page('select_idp_user.html', idp=idp,
                                      users=self.master_password_manager.get_users_for_idp(idp),
                                      message='Error: Error registering the new user!')

        master_username = self.master_password_manager.username
        master_password = self.master_password_manager.master_password
        self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                 idp_user=username, idp=idp)

        self.password_manager.password = password.encode()
        if referer:
            raise cherrypy.HTTPRedirect(referer, status=303)

    @cherrypy.expose
    def update_idp_credentials(self, **kwargs):
        # verify if the user is authenticated
        if not self.master_password_manager:
            return self.__render_page('keychain.html', action='update_idp')

        if cherrypy.request.method == 'GET':
            return self.__render_page('update_idp_cred.html', idps=self.master_password_manager.idps)

        elif cherrypy.request.method == 'POST':
            if 'idp_user' not in kwargs:
                return self.__render_page('update_idp_cred.html', idps=self.master_password_manager.idps,
                                          message="Error: You must select a user to update!")

            indexes = [int(v) for v in kwargs['idp_user'].split('_')]

            selected_idp = list(self.master_password_manager.idps.keys())[indexes[0]]
            selected_user = self.master_password_manager.idps[selected_idp][indexes[1]]

            message = self.update_idp_user_credentials(idp_user=selected_user, idp=selected_idp,
                                                       username=kwargs['username'] if 'username' in kwargs else '',
                                                       password=kwargs['password'] if 'password' in kwargs else '')

            if not message:
                message = 'Success: The user was updated with success'

            return self.__render_page('update_idp_cred.html', idps=self.master_password_manager.idps,
                                      message=message)

        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def update_idp_user(self, **kwargs):
        idp_user = self.password_manager.idp_username

        if cherrypy.request.method == 'GET':
            return self.__render_page('update_idp_user.html', idp=self.idp, user=idp_user)

        elif cherrypy.request.method == 'POST':
            message = self.update_idp_user_credentials(idp_user=idp_user, idp=self.idp,
                                                       username=kwargs['username'] if 'username' in kwargs else '',
                                                       password=kwargs['password'] if 'password' in kwargs else '')
            if message:
                return self.__render_page('update_idp_user.html', idp=self.idp, user=idp_user,
                                          message=message)

            if not self.register_biometric:
                self.zkp_auth(restart=True)
            else:
                raise cherrypy.HTTPRedirect(create_get_url(self.sso_url, params={
                    'methods': base64.urlsafe_b64encode(json.dumps(['zkp']).encode())
                }), status=303)
        else:
            raise cherrypy.HTTPError(405)

    def update_idp_user_credentials(self, idp_user: str, idp: str, username: str = '', password: str = '') -> str:
        master_username = self.master_password_manager.username

        # update username
        if username:
            if not self.master_password_manager.update_idp_user(previous_idp_user=idp_user, idp=idp,
                                                                new_idp_user=username):
                return "Error: Error updating the user's username!"
            Password_Manager.update_idp_username(master_username=master_username,
                                                 previous_idp_user=idp_user, idp=idp,
                                                 new_idp_user=username)

            idp_user = username

        # update password
        if password:
            master_password = self.master_password_manager.master_password
            self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                     idp_user=idp_user, idp=idp)

            if not self.password_manager.update_idp_password(new_password=password.encode()):
                return "Error: Error updating the user's password!"

        return ''

    @cherrypy.expose
    def update(self, **kwargs):
        if cherrypy.request.method == 'GET':
            return self.__render_page('keychain.html', action='update')

        elif cherrypy.request.method == 'POST':
            username = ''
            password = ''
            if 'username' in kwargs and kwargs['username']:
                username = kwargs['username']
            if 'password' in kwargs and kwargs['password']:
                password = kwargs['password'].encode()

            prev_username = self.master_password_manager.username
            if not self.master_password_manager.update_user(new_username=username, new_password=password):
                return self.__render_page('update.html', message='Error: Error updating the user!')

            # update the key files
            if username:
                Password_Manager.update_keychain_user(prev_username=prev_username, new_username=username,
                                                      idps=self.master_password_manager.idps)

            return self.__render_page('update.html', message='Success: The user was updated with success')

        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def attribute_presentation(self):
        response_attrs = {}
        if self.response_attrs_b64:
            response_attrs = json.loads(base64.b64decode(self.response_attrs_b64))
        return self.__render_page('attr_presentation.html', idp=self.idp, sp=self.sp,
                                  response_attrs=response_attrs,
                                  message=f"The IdP could not authenticate with success! <br> {self.message}"
                                  if not response_attrs else "")

    @cherrypy.expose
    def authorize_attr_response(self, **kwargs):
        if 'deny' in kwargs:
            return self.__render_page('auth_refused.html')

        elif 'allow' in kwargs:
            return self.__render_page('post_id_attr.html', consumer_url=self.consumer_url,
                                      response=self.response_attrs_b64,
                                      methods_successful=self.methods_successful_b64,
                                      methods_unsuccessful=self.methods_unsuccessful_b64,
                                      signature=self.response_signature_b64,
                                      client=self.sp_client)

    @cherrypy.expose
    def zkp(self, password: str):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        password = password.encode()
        self.password_manager.password = password
        self.zkp_auth()

    @cherrypy.expose
    def authenticate(self, max_iterations, min_iterations, client, key, method, auth_url, save_pk_url, id_url, auth_bio,
                     reg_bio):
        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        self.idp_client = client

        key = base64.urlsafe_b64decode(key)
        self.cipher_auth = Cipher_Authentication(key=key)

        self.auth_url = auth_url
        self.save_pk_url = save_pk_url
        self.id_url = id_url
        self.auth_bio = auth_bio
        self.reg_bio = reg_bio

        if method in ['face', 'fingerprint']:
            return self.__render_page('biometric_auth.html', idp=self.idp, method=method, operation='verify',
                                      submit=len(self.username) > 0, username=self.username)
        else:
            self.max_idp_iterations = int(max_iterations)

            self.min_idp_iterations = int(min_iterations)
            if overlap_intervals(MIN_ITERATIONS_ALLOWED, MAX_ITERATIONS_ALLOWED,
                                 self.min_idp_iterations, self.max_idp_iterations):
                self.iterations = random.randint(max(MIN_ITERATIONS_ALLOWED, self.min_idp_iterations),
                                                 min(MAX_ITERATIONS_ALLOWED, self.max_idp_iterations))
            else:
                self.iterations = 0
                raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/error",
                                                           params={'error_id': 'idp_iterations'}), 301)

            # verify if the user is authenticated
            if not self.master_password_manager:
                return self.__render_page('keychain.html', action='auth')

            if self.register_biometric:
                self.zkp_auth()
                # raise cherrypy.HTTPRedirect(create_get_url("{HELPER_URL}/biometric_face",
                #                                            params={'username': '', 'operation': 'register'}), 301)

            return self.__render_page('select_idp_user.html', idp=self.idp,
                                      users=self.master_password_manager.get_users_for_idp(self.idp))

    @cherrypy.expose
    def choose_iterations(self, **kwargs):
        if self.iterations != 0:
            raise cherrypy.HTTPError(401)

        if cherrypy.request.method == 'GET':
            return self.__render_page('choose_iterations.html', idp=self.idp,
                                      max_iterations=self.max_idp_iterations,
                                      min_iterations=self.min_idp_iterations)

        elif cherrypy.request.method == 'POST':
            if 'deny' in kwargs:
                return self.__render_page('auth_refused.html')

            elif 'allow' in kwargs:
                if ('iterations' not in kwargs or not kwargs['iterations']
                        or not kwargs['iterations'].isnumeric() or not int(kwargs['iterations'])):
                    return self.__render_page('choose_iterations.html', idp=self.idp,
                                              max_iterations=self.max_idp_iterations,
                                              min_iterations=self.min_idp_iterations,
                                              message="Error: You must select a number of iterations to use for the authentication!")

                self.iterations = int(kwargs['iterations'])
                # if we want to verify the number of iterations allowed by the IdP a priori
                # if self.iterations < self.min_idp_iterations or self.iterations > self.max_idp_iterations:
                #     return Template(filename='helper/static/choose_iterations.html').render(
                #         idp=self.idp,
                #         max_iterations=self.max_idp_iterations,
                #         min_iterations=self.min_idp_iterations,
                #         message="Error: You must select a number of iterations belonging to the Identity Provider "
                #                 "allowed interval, or deny the connection!")

                return self.__render_page('keychain.html', action='auth')

        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def register(self, **kwargs):
        if cherrypy.request.method == 'GET':
            return self.__render_page('register.html')

        elif cherrypy.request.method == 'POST':
            username = kwargs['username']
            master_password = kwargs['password'].encode()

            if not username or not master_password:
                return self.jinja_env.get_template('register.html').render(
                    message='Error: You must introduce a username and a password!')

            self.master_password_manager = Master_Password_Manager(username=username, master_password=master_password)
            if not self.master_password_manager.register_user():
                self.master_password_manager = None
                return self.__render_page('register.html', message='Error: The inserted user already exists!')

            return self.__render_page('register.html', message='Success: The user was registered with success')

        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def biometric_register(self, **kwargs):
        # verify if the user is authenticated
        if not self.master_password_manager:
            return self.__render_page('keychain.html', action='biometric_register')

        if cherrypy.request.method == 'GET':
            return self.__render_page('biometric_register.html', idps=self.master_password_manager.idps)

        elif cherrypy.request.method == 'POST':
            if 'idp_user' not in kwargs:
                return self.__render_page('biometric_register.html', idps=self.master_password_manager.idps,
                                          message="Error: You must select a user to update!")

            elif 'method' not in kwargs:
                return self.__render_page('biometric_register.html', idps=self.master_password_manager.idps,
                                          message="Error: You must select the biometric method you want to register with!")

            indexes = [int(v) for v in kwargs['idp_user'].split('_')]

            selected_idp = list(self.master_password_manager.idps.keys())[indexes[0]]
            selected_user = self.master_password_manager.idps[selected_idp][indexes[1]]

            # TODO -> VER ISTO
            self.sso_url = f"{selected_idp}/login"
            self.idp = selected_idp

            self.register_biometric = True
            master_username = self.master_password_manager.username
            master_password = self.master_password_manager.master_password
            self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                     idp_user=selected_user, idp=self.idp)

            self.registration_method = kwargs['method']

            # load password
            if not self.password_manager.load_password():
                raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/error",
                                                           params={'error_id': 'load_pass_error'}), 301)

            raise cherrypy.HTTPRedirect(create_get_url(self.sso_url, params={
                'methods': base64.urlsafe_b64encode(json.dumps(['zkp']).encode())
            }), status=303)
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def biometric_face(self, operation, **kwargs):
        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        data_render = {
            'ws_url': f"{HELPER_URL_WS}/{self.instructions_ws.__name__}",
            'operation': operation,
            'operation_message': "Face Verification" if operation == 'verify' else "Face Registration",
            'idp': self.idp
        }
        if 'username' in kwargs:
            self.username = kwargs['username']
            data_render['username'] = self.username

        return self.__render_page('face.html', **data_render)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def biometric_face_api(self, operation, **kwargs):
        if not self.cipher_auth:
            cherrypy.response.status = 302
            return {'url': '/biometric_register'}

        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        self.face_biometry = Face_biometry(ws=self.ws_publish)

        if operation == 'verify':
            if 'username' not in kwargs:
                cherrypy.response.status = 500
                return {'message': "The IdP was not able to login with face"}

            features = self.face_biometry.get_facial_features(number_faces=1)
            while True:
                if ws_queue.get() == 'send':
                    break
                elif ws_queue.get() in ['restart', 'stop']:
                    cherrypy.response.status = 500
                    return

            id_attrs_b64 = base64.urlsafe_b64encode(json.dumps(self.id_attrs).encode())

            ciphered_params = self.cipher_auth.create_response({
                'id_attrs': id_attrs_b64.decode(),
                'username': kwargs['username'],
                'features': features
            })

            response = requests.get(self.auth_bio, params={
                'client': self.idp_client,
                **ciphered_params
            })

            print(response.__dict__)

            if response.status_code != 200 and response.status_code != 401:
                # TODO ->  ANALISAR QUAL O FLOW A SER SEGUIDO
                print(f"Error status: {response.status_code}")
                # self.zkp_auth()
                cherrypy.response.status = 500
                self.message = "The IdP was not able to login with face"
                # return {'message': "The IdP was not able to login with face"}
            else:
                response_dict = self.cipher_auth.decipher_response(response.json())
                if response_dict['redirect']:
                    cherrypy.response.status = response_dict['status_code']
                    return {'url': response_dict['url']}
                    # raise cherrypy.HTTPRedirect(response_dict['url'], status=response_dict['status_code'])

                if response.status_code == 200:
                    self.response_attrs_b64 = response_dict['response']
                    self.response_signature_b64 = response_dict['signature']

                self.methods_successful_b64 = base64.urlsafe_b64encode(
                    json.dumps(response_dict['methods_successful']).encode()).decode()
                self.methods_unsuccessful_b64 = base64.urlsafe_b64encode(
                    json.dumps(response_dict['methods_unsuccessful']).encode()).decode()

            cherrypy.response.status = 302
            return {'url': '/attribute_presentation'}
        elif operation == 'register':
            self.register_biometric = False

            features = self.face_biometry.get_facial_features(number_faces=NUMBER_FACES_REGISTER)
            while True:
                if ws_queue.get() == 'send':
                    break
                elif ws_queue.get() in ['restart', 'stop']:
                    cherrypy.response.status = 500
                    return

            ciphered_params = self.cipher_auth.create_response({
                'features': features
            })

            response = requests.get(self.reg_bio, params={
                'client': self.idp_client,
                'method': 'face',
                **ciphered_params
            })

            if response.status_code != 200:
                # TODO ->  ANALISAR MENSAGEM DE ERRO
                print(f"Error received from idp on function <{self.biometric_face.__name__}>: "
                      f"<{response.status_code}: {response.reason}>")
                cherrypy.response.status = 500
                return {'message': "There was an error registering this user's face on the selected IdP.",
                        'status': False}
            else:
                return {'message': 'The faces where registered on the IdP with success!',
                        'status': True}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def biometric_fingerprint_api(self, operation, **kwargs):
        # if not self.cipher_auth:
        #     cherrypy.response.status = 302
        #     return {'url': '/biometric_register'}

        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        self.fingerprint = Fingerprint()
        setup_status = self.fingerprint.setup()

        if not setup_status.get('is_ready'):
            cherrypy.response.status = 500
            return {'message': setup_status.get('message')}

        # Delete this
        name, side, index_finger = kwargs.get('name'), kwargs.get('side'), kwargs.get('index')

        for flow in self.fingerprint.get_fingerprint(operation, name, side, index_finger):
            status, message, phase = flow.get('status'), flow.get('message'), flow.get('phase')

            if not status:
                cherrypy.response.status = 500
                return {'message': message}

            self.ws_publish(message)

            if phase == IMAGE_DATA:
                fingerprint_image = flow.get('data')
                self.ws_publish(base64.b64encode(fingerprint_image).decode(), operation="fingerprint_image")

            elif phase == VALID_IMAGE:
                self.ws_publish(operation='valid_image')

            elif phase == ALL_IMAGES_VALID:
                self.ws_publish(operation='all_images')
                while True:
                    msg = ws_queue.get()
                    print(msg)
                    if msg == 'send':
                        break
                    elif msg in ['stop']:
                        self.fingerprint.clear_buffer()
                        cherrypy.response.status = 500
                        return {'message': 'Client disconnected'}

        self.ws_publish("\nCreating the image's descriptors (This action can take a few seconds)...\n")
        descriptors = self.fingerprint.get_descriptors()

        if not descriptors:
            cherrypy.response.status = 500
            return {'message': FINGERPRINT_ERRORS.get("DESCRIPTORS_ERROR")}

        descriptors = base64.b64encode(descriptors).decode()

        if operation == 'verify':
            id_attrs_b64 = base64.urlsafe_b64encode(json.dumps(self.id_attrs).encode())

            ciphered_params = self.cipher_auth.create_response({
                'id_attrs': id_attrs_b64.decode(),
                'username': kwargs['username'],
                'fingerprint_descriptors': descriptors
            })

            response = requests.get(self.auth_bio, params={
                'client': self.idp_client,
                **ciphered_params
            })

            if response.status_code != 200 and response.status_code != 401:
                cherrypy.response.status = 500
                self.message = FINGERPRINT_ERRORS.get("LOGIN_ERROR")
                # return {'message': FINGERPRINT_ERRORS.get("LOGIN_ERROR")}
            else:
                response_dict = self.cipher_auth.decipher_response(response.json())
                if response_dict['redirect']:
                    cherrypy.response.status = response_dict['status_code']
                    return {'url': response_dict['url']}

                if response.status_code == 200:
                    self.response_attrs_b64 = response_dict['response']
                    self.response_signature_b64 = response_dict['signature']

                self.methods_successful_b64 = base64.urlsafe_b64encode(
                    json.dumps(response_dict['methods_successful']).encode()).decode()
                self.methods_unsuccessful_b64 = base64.urlsafe_b64encode(
                    json.dumps(response_dict['methods_unsuccessful']).encode()).decode()

            cherrypy.response.status = 302
            return {'url': '/attribute_presentation'}

        elif operation == 'register':
            self.register_biometric = False

            ciphered_params = self.cipher_auth.create_response({
                'fingerprint_descriptors': descriptors
            })

            response = requests.post(self.reg_bio, data={
                'client': self.idp_client,
                'method': 'fingerprint',
                **ciphered_params
            })

            if response.status_code != 200:
                cherrypy.response.status = 500
                return {'message': FINGERPRINT_ERRORS.get("REGISTER_ERROR")}

            self.ws_publish("Fingerprint model saved in IDP")
            return {'message': 'Success'}

    @cherrypy.expose
    def biometric_fingerprint(self, operation, **kwargs):
        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        data_render = {
            'ws_url': f"{HELPER_URL_WS}/{self.instructions_ws.__name__}",
            'operation': operation,
            'operation_message': "Fingerprint Verification" if operation == 'verify' else "Fingerprint Registration",
            'idp': self.idp
        }

        return self.__render_page('fingerprint.html', **data_render)

    def __biometric_registration_final(self):
        if self.registration_method == 'face':
            raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/biometric_face",
                                                       params={'operation': 'register'}), 301)

        elif self.registration_method == 'fingerprint':
            raise cherrypy.HTTPRedirect(create_get_url(f"{HELPER_URL}/biometric_fingerprint",
                                                       params={'operation': 'register'}), 301)

    @cherrypy.expose
    def instructions_ws(self):
        pass

    def ws_publish(self, message='', operation='instruction', channel="websocket-broadcast"):
        data = {
            'content': message,
            'operation': operation
        }
        cherrypy.engine.publish(channel, json.dumps(data))


if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host': HELPER_HOST_NAME,
                            'server.socket_port': HELPER_PORT})

    WebSocketPlugin(cherrypy.engine).subscribe()
    cherrypy.tools.websocket = WebSocketTool()

    cherrypy.quickstart(HelperApp(), '', config={
        f'/{HelperApp.instructions_ws.__name__}': {
            'tools.websocket.on': True,
            'tools.websocket.handler_cls': WebSocketHandler
        }
    })
