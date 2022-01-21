import base64
import json
import typing
import uuid
from datetime import datetime, timedelta
from os import urandom
from pathlib import Path

import cherrypy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from idp.biometric_systems.facial.facial_recognition import Face_biometry
from idp.biometric_systems.fingerprint.fingerprint import Fingerprint
from idp.queries import setup_database, get_user, save_user_key, get_user_key, save_user, check_credentials, \
    update_user, delete_user, save_faces, get_faces, save_fingerprint, get_fingerprint
from utils.utils import ZKP_IdP, asymmetric_padding_signature, asymmetric_hash, create_get_url, \
    Cipher_Authentication, \
    asymmetric_upload_derivation_key, asymmetric_padding_encryption

from jinja2 import Environment, FileSystemLoader

HOST_NAME = '127.0.0.1'
HOST_PORT = 8082
# noinspection HttpUrlsUsage
HOST_URL = f"http://{HOST_NAME}:{HOST_PORT}"

HELPER_HOST_NAME = "127.1.2.3"  # zkp_helper_app
HELPER_PORT = 1080
HELPER_URL = f"http://{HELPER_HOST_NAME}:{HELPER_PORT}"

MIN_ITERATIONS_ALLOWED = 300
MAX_ITERATIONS_ALLOWED = 1000
KEYS_TIME_TO_LIVE = 10  # minutes

KEY_PATH_NAME = f"idp/idp_keys/server.key"

zkp_values: typing.Dict[str, ZKP_IdP] = {}


class Asymmetric_IdP(object):
    def __init__(self):
        with open(KEY_PATH_NAME, 'rb') as file:
            pem = file.read()

        self.private_key = load_pem_private_key(
            data=pem,
            password=None,
            backend=default_backend()
        )

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data=data, padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())


class IdP(Asymmetric_IdP):
    def __init__(self):
        super().__init__()
        self.jinja_env = Environment(loader=FileSystemLoader('idp/static'))

    def __redirect_helper_authentication(self, client_id: str):
        return create_get_url(f"{HELPER_URL}/authenticate",
                                                   params={
                                                       'max_iterations': MAX_ITERATIONS_ALLOWED,
                                                       'min_iterations': MIN_ITERATIONS_ALLOWED,
                                                       'client': client_id,
                                                       'method': zkp_values[client_id].next_method(),
                                                       'key': base64.urlsafe_b64encode(zkp_values[client_id].key),
                                                       'auth_url': f"{HOST_URL}/{self.authenticate.__name__}",
                                                       'save_pk_url': f"{HOST_URL}/{self.save_asymmetric.__name__}",
                                                       'id_url': f"{HOST_URL}/{self.identification.__name__}",
                                                       'auth_bio': f"{HOST_URL}/{self.biometric_authentication.__name__}",
                                                       'reg_bio': f"{HOST_URL}/{self.biometric_register.__name__}",
                                                   })

    @cherrypy.expose
    def index(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login_locally')

        raise cherrypy.HTTPRedirect('/account')

    @cherrypy.expose
    def logout(self):
        # Clear session
        cherrypy.session.clear()
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def login_locally(self):
        return self.jinja_env.get_template('login.html').render()

    @cherrypy.expose
    def sign_up(self):
        return self.jinja_env.get_template('sign_up.html').render()

    @cherrypy.expose
    def account(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login_locally')

        user = get_user(user_id, 'id', as_dict=True)
        template = self.jinja_env.get_template('account.html')
        return template.render(id=user.get('id'), username=user.get('username'))

    @cherrypy.expose
    def login(self, methods, minimum_methods='1'):
        client_id = str(uuid.uuid4())

        aes_key = urandom(32)
        # TODO -> MUDAR ISTO
        zkp_values[client_id] = ZKP_IdP(methods=methods, minimum_methods=int(minimum_methods), key=aes_key,
                                        max_iterations=MAX_ITERATIONS_ALLOWED)
        raise cherrypy.HTTPRedirect(self.__redirect_helper_authentication(client_id=client_id), 303)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def create_account(self, username, password):
        creation_status = save_user(username, password)
        if not creation_status:
            raise cherrypy.HTTPError(500, message='Error creating new account')

        raise cherrypy.HTTPRedirect('/login_locally')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def update_account(self, user_id, password, **kwargs):
        saved_user = get_user(user_id, 'id', as_dict=True)
        password_correctness_status = check_credentials(saved_user.get('username'), password)

        if not password_correctness_status:
            raise cherrypy.HTTPError(403, message='Wrong password')

        kwargs['password'] = kwargs.pop('new_password', None)

        new_args = {}
        for field_name, field_content in kwargs.items():
            if field_name == "password" and check_credentials(saved_user.get('username'), field_content):
                continue
            if len(field_content) == 0 or saved_user.get(field_name) == field_content:
                continue
            new_args[field_name] = field_content

        if len(new_args) == 0:
            return {'status': 'NOTHING'}

        update_status = update_user(user_id, new_args)
        if not update_status:
            raise cherrypy.HTTPError(500, message='Error while updating account')

        return {'status': 'OK'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def delete_account(self, user_id, password):
        saved_user = get_user(user_id, 'id', as_dict=True)
        password_correctness_status = check_credentials(saved_user.get('username'), password)

        if not password_correctness_status:
            raise cherrypy.HTTPError(403, message='Wrong password')

        removal_status = delete_user(user_id)
        if not removal_status:
            raise cherrypy.HTTPError(500, message='Error while deleting account')

        return {'status': 'OK'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def authenticate_locally(self, username, password):
        login_status = check_credentials(username, password)
        if not login_status:
            raise cherrypy.HTTPError(403, message='Wrong credentials')

        cherrypy.session['user_id'] = get_user(username, as_dict=True).get('id')
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def authenticate(self, **kwargs):
        client_id = kwargs['client']
        current_zkp = zkp_values[client_id]
        request_args = current_zkp.decipher_response(kwargs)

        method = current_zkp.current_method

        # restart zkp
        if 'restart' in request_args and request_args['restart']:
            zkp_values[client_id] = ZKP_IdP(methods=method, key=current_zkp.key,
                                            max_iterations=MAX_ITERATIONS_ALLOWED)
            zkp_values[client_id].current_method = method
            current_zkp = zkp_values[client_id]

        challenge = request_args['nonce'].encode()
        if current_zkp.iteration < 2:
            if 'username' in request_args:
                username = str(request_args['username'])
                current_zkp.username = username
                current_zkp.password = get_user(username, as_dict=True).get('password', '').encode()
            else:
                del current_zkp
                raise cherrypy.HTTPError(400,
                                         message='The first request to this endpoint must have the parameter username')
            if 'iterations' in request_args:
                iterations = int(request_args['iterations'])
                if MIN_ITERATIONS_ALLOWED <= iterations <= MAX_ITERATIONS_ALLOWED:
                    current_zkp.max_iterations = iterations
                else:
                    del current_zkp
                    raise cherrypy.HTTPError(406, message='The number of iterations does not met the defined range')
        else:
            current_zkp.verify_challenge_response(int(request_args['response']))

        challenge_response = current_zkp.response(challenge)
        nonce = current_zkp.create_challenge()

        return current_zkp.create_response({
            'nonce': nonce,
            'response': challenge_response
        })

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def save_asymmetric(self, **kwargs):
        client_id = kwargs['client']
        current_zkp = zkp_values[client_id]

        if current_zkp.iteration >= current_zkp.max_iterations * 2 and current_zkp.all_ok:
            key = asymmetric_upload_derivation_key(current_zkp.responses, current_zkp.iteration, 32)
            asymmetric_cipher_auth = Cipher_Authentication(key=key)

            request_args = asymmetric_cipher_auth.decipher_response(current_zkp.decipher_response(kwargs))
            key = request_args['key']
            user_id = str(uuid.uuid4())
            status = save_user_key(id=user_id, username=current_zkp.username,
                                   key=key,
                                   not_valid_after=(datetime.now() + timedelta(minutes=KEYS_TIME_TO_LIVE)).timestamp())
            return current_zkp.create_response(asymmetric_cipher_auth.create_response({
                'status': status,
                'ttl': KEYS_TIME_TO_LIVE,
                'user_id': user_id
            }))
        else:
            raise cherrypy.HTTPError(401, message="ZKP protocol was not completed")

    def __get_id_attrs(self, id_attrs_b64, username) -> (bytes, bytes):
        id_attrs = json.loads(base64.urlsafe_b64decode(id_attrs_b64))

        response_dict = dict()
        if 'username' in id_attrs:
            response_dict['username'] = username
        '''add here more attributes if needed'''

        response_b64 = base64.urlsafe_b64encode(json.dumps(response_dict).encode())
        response_signature_b64 = base64.urlsafe_b64encode(self.sign(response_b64))

        return response_b64, response_signature_b64

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def identification(self, **kwargs):
        def __redirect_or_end(current_zkp: ZKP_IdP):
            try:
                return current_zkp.create_response({
                    'redirect': True,
                    'status_code': 303,
                    'url': self.__redirect_helper_authentication(client_id=client_id)
                })
            except IndexError:
                cherrypy.response.status = 401
                return current_zkp.create_response({
                    'redirect': False,
                    'methods_unsuccessful': list(current_zkp.methods_unsuccessful),
                    'methods_successful': list(current_zkp.methods_successful),
                    'message': 'Authentication failed'
                })

        client_id = kwargs['client']
        current_zkp = zkp_values[client_id]
        request_args = current_zkp.decipher_response(kwargs)

        user_id = request_args['user_id']
        username = request_args['username']
        id_attrs_b64 = request_args['id_attrs'].encode()
        id_attrs_signature_b64 = base64.urlsafe_b64decode(request_args['signature'])

        public_key_db = get_user_key(id=user_id, username=username)
        if public_key_db and len(public_key_db) > 0:
            if public_key_db[1] > datetime.now().timestamp():  # verify if the key is not expired
                public_key = load_pem_public_key(data=public_key_db[0].encode(), backend=default_backend())

                # verify if the signature is valid
                try:
                    public_key.verify(signature=id_attrs_signature_b64, data=id_attrs_b64,
                                      padding=asymmetric_padding_signature(), algorithm=asymmetric_hash())
                except InvalidSignature:
                    current_zkp.methods_unsuccessful.add('zkp')
                    __redirect_or_end(current_zkp)
                    # raise cherrypy.HTTPError(401, message="Authentication failed")

                response_b64, response_signature_b64 = self.__get_id_attrs(id_attrs_b64, username)

                aes_key = urandom(32)
                iv = urandom(16)
                new_cipher = Cipher_Authentication(aes_key)
                ciphered_aes_key = base64.urlsafe_b64encode(public_key.encrypt(
                    aes_key, padding=asymmetric_padding_encryption()
                ))
                response = new_cipher.cipher_data({
                    'response': response_b64.decode(),
                    'signature': response_signature_b64.decode()
                }, iv=iv)

                current_zkp.methods_successful.add('zkp')
                if len(current_zkp.methods_successful) >= current_zkp.minimum_methods:
                    return current_zkp.create_response({
                        'redirect': False,
                        'methods_unsuccessful': list(current_zkp.methods_unsuccessful),
                        'methods_successful': list(current_zkp.methods_successful),
                        'ciphered_aes_key': ciphered_aes_key.decode(),
                        'iv': base64.urlsafe_b64encode(iv).decode(),
                        'response': response
                    })

                return __redirect_or_end(current_zkp)
            else:
                raise cherrypy.HTTPError(410, message="Expired key")
        else:
            raise cherrypy.HTTPError(424, message="No public key for the given user id and username")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def biometric_authentication(self, **kwargs):
        client_id = kwargs['client']
        current_zkp = zkp_values[client_id]
        request_args = current_zkp.decipher_response(kwargs)

        username = request_args['username']

        method = current_zkp.current_method
        auth_success = False

        if method == 'face':
            face_biometry = Face_biometry(username, save_faces_funct=save_faces, get_faces_funct=get_faces)
            auth_success = face_biometry.verify_user(request_args['features'])
        elif method == 'fingerprint':
            fingerprint = Fingerprint(username, get_fingerprint_func=get_fingerprint)
            auth_success = fingerprint.verify_user(base64.b64decode(request_args.get('fingerprint_descriptors')))
        else:
            raise cherrypy.HTTPError(403, message="Authentication method does not correspond with this endpoint")

        if auth_success:
            current_zkp.methods_successful.add(method)
        else:
            current_zkp.methods_unsuccessful.add(method)

        print(current_zkp.methods_successful)
        if len(current_zkp.methods_successful) >= current_zkp.minimum_methods:
            id_attrs_b64 = request_args['id_attrs'].encode()
            response_b64, response_signature_b64 = self.__get_id_attrs(id_attrs_b64=id_attrs_b64, username=username)
            return current_zkp.create_response({
                'redirect': False,
                'response': response_b64.decode(),
                'signature': response_signature_b64.decode(),
                'methods_unsuccessful': list(current_zkp.methods_unsuccessful),
                'methods_successful': list(current_zkp.methods_successful),
            })
        else:
            try:
                return current_zkp.create_response({
                    'redirect': True,
                    'status_code': 303,
                    'url': self.__redirect_helper_authentication(client_id=client_id)
                })
            except IndexError:
                cherrypy.response.status = 401
                return current_zkp.create_response({
                    'redirect': False,
                    'methods_unsuccessful': list(current_zkp.methods_unsuccessful),
                    'methods_successful': list(current_zkp.methods_successful),
                    'message': 'Authentication failed'
                })

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def biometric_register(self, method: str, **kwargs):
        # TODO -> COLOCAR ISTO EM POST
        client_id = kwargs['client']
        current_zkp = zkp_values[client_id]
        request_args = current_zkp.decipher_response(kwargs)

        if current_zkp.iteration >= current_zkp.max_iterations * 2 and current_zkp.all_ok:
            if method == 'face':
                face_biometry = Face_biometry(current_zkp.username, save_faces_funct=save_faces,
                                              get_faces_funct=get_faces)

                status = face_biometry.register_new_user(faces_features=request_args['features'])

                return current_zkp.create_response({
                    'status': status,
                })

            elif method == 'fingerprint':
                fingerprint = Fingerprint(current_zkp.username, save_fingerprint_func=save_fingerprint)
                status = fingerprint.register_new_user(base64.b64decode(request_args.get('fingerprint_descriptors')))

                return current_zkp.create_response({
                    'status': status,
                })
        else:
            raise cherrypy.HTTPError(401, message="ZKP protocol was not completed")


if __name__ == '__main__':
    Path("idp/sessions").mkdir(parents=True, exist_ok=True)
    setup_database()

    cherrypy.config.update({
        'server.socket_host': HOST_NAME,
        'server.socket_port': HOST_PORT,
        'server.thread_pool': 20,
        'tools.sessions.on': True,
        'tools.sessions.storage_type': "File",
        'tools.sessions.storage_path': 'idp/sessions',
        'tools.sessions.timeout': 60,
        'tools.sessions.clean_freq': 10,
        'tools.sessions.name': 'idp_session_id',
    })
    cherrypy.quickstart(IdP())
