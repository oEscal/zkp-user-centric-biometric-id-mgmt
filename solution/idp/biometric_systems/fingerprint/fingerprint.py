import adafruit_fingerprint
import serial

FINGERPRINT_ERRORS = {
    'NOT_READY': "Error in sensor's initialization; Refresh the page to try again",
    'REGISTER_ERROR': "There was an error registering this user's fingerprint on the selected IdP.",
    'LOGIN_ERROR': "The IdP was no able to login with face"
}


class Fingerprint:
    def __init__(self, username, save_fingerprint_func=None, get_fingerprint_func=None):
        self.username = username
        self.save_fingerprint_func = save_fingerprint_func
        self.get_fingerprint_func = get_fingerprint_func
        self.uart = None
        self.finger = None

    def setup(self):
        try:
            self.uart = serial.Serial("/dev/ttyUSB0", baudrate=57600, timeout=1)
            self.finger = adafruit_fingerprint.Adafruit_Fingerprint(self.uart)
            return {'is_ready': True, 'message': None}
        except Exception as e:
            print(e)
            return {'is_ready': False, 'message': FINGERPRINT_ERRORS['NOT_READY']}

    def register_new_user(self, model_data):
        if not self.save_fingerprint_func:
            raise NotImplementedError("Save fingerprint function does not exists")
        return self.save_fingerprint_func(self.username, model_data)

    def verify_user(self, model_data):
        if not self.get_fingerprint_func:
            raise NotImplementedError("Get fingerprint function does not exists")

        saved_fingerprint = list(self.get_fingerprint_func(self.username))
        self.finger.send_fpdata(model_data, "char", 1)
        self.finger.send_fpdata(saved_fingerprint, "char", 2)

        return self.finger.compare_templates() == adafruit_fingerprint.OK
