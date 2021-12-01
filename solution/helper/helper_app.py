import base64
import json
import random

import cherrypy
import requests
from mako.template import Template

from helper.biometric_systems.facial.facial_recognition import Face_biometry
from utils.utils import ZKP, overlap_intervals, \
    Cipher_Authentication, asymmetric_upload_derivation_key, create_get_url
from helper.managers import Master_Password_Manager, Password_Manager
from jinja2 import Environment, FileSystemLoader

MIN_ITERATIONS_ALLOWED = 200
MAX_ITERATIONS_ALLOWED = 500

NUMBER_FACES_REGISTER = 7


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

        self.max_idp_iterations = 0
        self.min_idp_iterations = 0

        self.response_attrs_b64 = ''
        self.response_signature_b64 = ''

        self.jinja_env = Environment(loader=FileSystemLoader('helper/static'))
        self.face_biometry: Face_biometry = None  # = Face_biometry('escaleira')
        self.register_biometric = False
        self.registration_method = ''

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
            'face_register_error': "There was an error registering this user's face on the selected IdP."
        }
        return self.jinja_env.get_template('error.html').render(message=errors[error_id])

    @cherrypy.expose
    def login(self, sp: str, idp: str, id_attrs: str, consumer_url: str, sso_url: str, client: str):
        self.__init__()
        attrs = id_attrs.split(',')
        return self.jinja_env.get_template('login_attributes.html').render(sp=sp, idp=idp, id_attrs=attrs,
                                                                           sso_url=sso_url, consumer_url=consumer_url,
                                                                           client=client)

    @cherrypy.expose
    def authorize_attr_request(self, sp: str, idp: str, id_attrs: list, consumer_url: str, sso_url: str, client: str,
                               **kwargs):
        if 'deny' in kwargs:
            return self.jinja_env.get_template('auth_refused.html').render()
        elif 'allow' in kwargs:
            self.sp = sp
            self.idp = idp
            self.id_attrs = [e for e in id_attrs if e]
            self.consumer_url = consumer_url
            self.sso_url = sso_url
            self.sp_client = client

            raise cherrypy.HTTPRedirect(self.sso_url, status=303)

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
        if response.status_code != 200:
            print(f"Error status: {response.status_code}")
            self.zkp_auth()
        else:
            response_dict = self.cipher_auth.decipher_response(response.json())
            try:
                aes_key = self.password_manager.decrypt(base64.urlsafe_b64decode(response_dict['ciphered_aes_key']))
            except Exception as e:
                print(f"Error in function <{self.asymmetric_identification.__name__}>: <{e}>")
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'asy_error_decrypt'}), 301)

            iv = base64.urlsafe_b64decode(response_dict['iv'])
            new_cipher = Cipher_Authentication(aes_key)

            response_dict_attrs = new_cipher.decipher_data(
                data=response_dict['response'],
                iv=iv
            )
            self.response_attrs_b64 = response_dict_attrs['response']
            self.response_signature_b64 = response_dict_attrs['signature']

        raise cherrypy.HTTPRedirect("/attribute_presentation", 303)

    def zkp_auth(self, restart=False):
        # verify if zkp was already done previously
        if not restart and self.zkp is not None:
            raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                       params={'error_id': 'zkp_inf_cycle'}), 301)

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
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
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
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'zkp_save_keys'}), 301)

            response = asymmetric_cipher_auth.decipher_response(self.cipher_auth.decipher_response(response.json()))
            if 'status' in response and bool(response['status']):
                self.password_manager.save_private_key(user_id=response['user_id'], time_to_live=float(response['ttl']))
        else:
            raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                       params={'error_id': 'zkp_auth_error'}), 301)

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
            return self.jinja_env.get_template('keychain.html').render(action=action,
                                                                       message='Error: Unsuccessful login!')

        if action == 'auth':
            return self.jinja_env.get_template('select_idp_user.html').render(
                idp=self.idp,
                users=self.master_password_manager.get_users_for_idp(self.idp))
        elif action == 'update':
            return self.jinja_env.get_template('update.html').render()
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

        master_username = self.master_password_manager.username
        master_password = self.master_password_manager.master_password
        self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                 idp_user=idp_user, idp=self.idp)

        if not self.password_manager.load_password():
            raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                       params={'error_id': 'load_pass_error'}), 301)
        else:
            if not self.password_manager.load_private_key():
                self.zkp_auth()
            else:
                self.asymmetric_identification()

    @cherrypy.expose
    def add_idp_user(self, username: str, password: str):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        if not username or not password:
            return self.jinja_env.get_template("select_idp_user.html").render(
                idp=self.idp,
                users=self.master_password_manager.get_users_for_idp(self.idp),
                message='Error: You must enter a new username with a password!'
            )

        # update keychain registered idp users
        if not self.master_password_manager.add_idp_user(idp_user=username, idp=self.idp):
            return self.jinja_env.get_template(filename='select_idp_user.html').render(
                idp=self.idp,
                users=self.master_password_manager.get_users_for_idp(self.idp),
                message='Error: Error registering the new user!')

        master_username = self.master_password_manager.username
        master_password = self.master_password_manager.master_password
        self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                 idp_user=username, idp=self.idp)

        self.password_manager.password = password.encode()
        self.zkp_auth()

    @cherrypy.expose
    def update_idp_credentials(self, **kwargs):
        # verify if the user is authenticated
        if not self.master_password_manager:
            return self.jinja_env.get_template('keychain.html').render(action='update_idp')

        if cherrypy.request.method == 'GET':
            return self.jinja_env.get_template('update_idp_cred.html').render(
                idps=self.master_password_manager.idps)
        elif cherrypy.request.method == 'POST':
            if 'idp_user' not in kwargs:
                return self.jinja_env.get_template('update_idp_cred.html').render(
                    idps=self.master_password_manager.idps,
                    message="Error: You must select a user to update!")

            indexes = [int(v) for v in kwargs['idp_user'].split('_')]

            selected_idp = list(self.master_password_manager.idps.keys())[indexes[0]]
            selected_user = self.master_password_manager.idps[selected_idp][indexes[1]]

            message = self.update_idp_user_credentials(idp_user=selected_user, idp=selected_idp,
                                                       username=kwargs['username'] if 'username' in kwargs else '',
                                                       password=kwargs['password'] if 'password' in kwargs else '')

            if not message:
                message = 'Success: The user was updated with success'

            return self.jinja_env.get_template('update_idp_cred.html').render(
                idps=self.master_password_manager.idps,
                message=message)
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def update_idp_user(self, **kwargs):
        idp_user = self.password_manager.idp_username

        if cherrypy.request.method == 'GET':
            return self.jinja_env.get_template('update_idp_user.html').render(idp=self.idp, user=idp_user)
        elif cherrypy.request.method == 'POST':
            message = self.update_idp_user_credentials(idp_user=idp_user, idp=self.idp,
                                                       username=kwargs['username'] if 'username' in kwargs else '',
                                                       password=kwargs['password'] if 'password' in kwargs else '')
            if message:
                return self.jinja_env.get_template('update_idp_user.html').render(idp=self.idp, user=idp_user,
                                                                                  message=message)

            self.zkp_auth(restart=True)
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
            return self.jinja_env.get_template('keychain.html').render(action='update')
        elif cherrypy.request.method == 'POST':
            username = ''
            password = ''
            if 'username' in kwargs and kwargs['username']:
                username = kwargs['username']
            if 'password' in kwargs and kwargs['password']:
                password = kwargs['password'].encode()

            prev_username = self.master_password_manager.username
            if not self.master_password_manager.update_user(new_username=username, new_password=password):
                return self.jinja_env.get_template('update.html').render(message='Error: Error updating the user!')

            # update the key files
            if username:
                Password_Manager.update_keychain_user(prev_username=prev_username, new_username=username,
                                                      idps=self.master_password_manager.idps)

            return self.jinja_env.get_template('update.html').render(
                message='Success: The user was updated with success')
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def attribute_presentation(self):
        response_attrs = json.loads(base64.b64decode(self.response_attrs_b64))
        return self.jinja_env.get_template('attr_presentation.html').render(idp=self.idp, sp=self.sp,
                                                                            response_attrs=response_attrs)

    @cherrypy.expose
    def authorize_attr_response(self, **kwargs):
        if 'deny' in kwargs:
            return self.jinja_env.get_template('auth_refused.html').render()
        elif 'allow' in kwargs:
            return self.jinja_env.get_template('post_id_attr.html').render(consumer_url=self.consumer_url,
                                                                           response=self.response_attrs_b64,
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

        if method == 'face':
            return self.jinja_env.get_template('biometric_auth.html').render(idp=self.idp, method=method,
                                                                             operation='verify')
        else:
            self.max_idp_iterations = int(max_iterations)

            self.min_idp_iterations = int(min_iterations)
            if overlap_intervals(MIN_ITERATIONS_ALLOWED, MAX_ITERATIONS_ALLOWED,
                                 self.min_idp_iterations, self.max_idp_iterations):
                self.iterations = random.randint(max(MIN_ITERATIONS_ALLOWED, self.min_idp_iterations),
                                                 min(MAX_ITERATIONS_ALLOWED, self.max_idp_iterations))
            else:
                self.iterations = 0
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'idp_iterations'}), 301)

            # verify if the user is authenticated
            if not self.master_password_manager:
                return self.jinja_env.get_template('keychain.html').render(action='auth')

            if self.register_biometric:
                self.zkp_auth()
                # raise cherrypy.HTTPRedirect(create_get_url("http://zkp_helper_app:1080/biometric_face",
                #                                            params={'username': '', 'operation': 'register'}), 301)

            return self.jinja_env.get_template('select_idp_user.html').render(
                idp=self.idp,
                users=self.master_password_manager.get_users_for_idp(self.idp))

    @cherrypy.expose
    def choose_iterations(self, **kwargs):
        if self.iterations != 0:
            raise cherrypy.HTTPError(401)

        if cherrypy.request.method == 'GET':
            return self.jinja_env.get_template('choose_iterations.html').render(idp=self.idp,
                                                                                max_iterations=self.max_idp_iterations,
                                                                                min_iterations=self.min_idp_iterations)
        elif cherrypy.request.method == 'POST':
            if 'deny' in kwargs:
                return self.jinja_env.get_template('auth_refused.html').render()
            elif 'allow' in kwargs:
                if ('iterations' not in kwargs or not kwargs['iterations']
                        or not kwargs['iterations'].isnumeric() or not int(kwargs['iterations'])):
                    return self.jinja_env.get_template('choose_iterations.html').render(
                        idp=self.idp,
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

                return self.jinja_env.get_template('keychain.html').render(action='auth')
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def register(self, **kwargs):
        if cherrypy.request.method == 'GET':
            return self.jinja_env.get_template('register.html').render()
        elif cherrypy.request.method == 'POST':
            username = kwargs['username']
            master_password = kwargs['password'].encode()

            self.master_password_manager = Master_Password_Manager(username=username, master_password=master_password)
            if not self.master_password_manager.register_user():
                return self.jinja_env.get_template('register.html').render(
                    message='Error: The inserted user already exists!')
            return self.jinja_env.get_template('register.html').render(
                message='Success: The user was registered with success')
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def biometric_register(self, **kwargs):
        # verify if the user is authenticated
        if not self.master_password_manager:
            return self.jinja_env.get_template('keychain.html').render(action='biometric_register')

        if cherrypy.request.method == 'GET':
            return self.jinja_env.get_template('biometric_register.html').render(
                idps=self.master_password_manager.idps)
        elif cherrypy.request.method == 'POST':
            if 'idp_user' not in kwargs:
                return self.jinja_env.get_template('biometric_register.html').render(
                    idps=self.master_password_manager.idps,
                    message="Error: You must select a user to update!")
            elif 'method' not in kwargs:
                return self.jinja_env.get_template('biometric_register.html').render(
                    idps=self.master_password_manager.idps,
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

            # load password
            if not self.password_manager.load_password():
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'load_pass_error'}), 301)

            self.registration_method = kwargs['method']

            raise cherrypy.HTTPRedirect(create_get_url(self.sso_url, params={'method': 'zkp'}), status=303)
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def biometric_face(self, operation, **kwargs):
        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        self.face_biometry = Face_biometry()

        if operation == 'verify':
            if 'username' not in kwargs:
                return self.jinja_env.get_template('biometric_auth.html').render(
                    idps=self.master_password_manager.idps,
                    message="Error: You must indicate the username you want to login with on this IdP!")

            features = self.face_biometry.get_facial_features()

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

            if response.status_code != 200:
                # TODO ->  ANALISAR QUAL O FLOW A SER SEGUIDO
                print(f"Error status: {response.status_code}")
                self.zkp_auth()
            else:
                response_dict = self.cipher_auth.decipher_response(response.json())
                self.response_attrs_b64 = response_dict['response']
                self.response_signature_b64 = response_dict['signature']

            raise cherrypy.HTTPRedirect("/attribute_presentation", 303)
        elif operation == 'register':
            self.register_biometric = False

            features = []
            for i in range(NUMBER_FACES_REGISTER):
                features.append(self.face_biometry.get_facial_features())

            ciphered_params = self.cipher_auth.create_response({
                'features': features
            })

            print(self.reg_bio)
            response = requests.get(self.reg_bio, params={
                'client': self.idp_client,
                'method': 'face',
                **ciphered_params
            })

            if response.status_code != 200:
                # TODO ->  ANALISAR MENSAGEM DE ERRO
                print(f"Error received from idp on function <{self.biometric_face.__name__}>: "
                      f"<{response.status_code}: {response.reason}>")
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'face_register_error'}), 301)
            else:
                return 'Success'

    def __biometric_registration_final(self):
        if self.registration_method == 'face':
            raise cherrypy.HTTPRedirect(create_get_url("http://zkp_helper_app:1080/biometric_face",
                                                       params={'operation': 'register'}), 301)


if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host': '127.1.2.3',
                            'server.socket_port': 1080})
    cherrypy.quickstart(HelperApp())
