import adafruit_fingerprint
import serial
import time

FINGERPRINT_ERRORS = {
    'NOT_READY': "Error in sensor's initialization; Refresh the page to try again",
    'REGISTER_ERROR': "There was an error registering this user's fingerprint on the selected IdP.",
    'LOGIN_ERROR': "The IdP was no able to login with fingerprint"
}

FINGER_IMAGE_ACQUISITION = 0
TEMPLATE_CREATION = 1
FINGER_REMOVAL = 2
MODEL_CREATION = 3
MODEL_DATA = 4
ERROR = 5


class Fingerprint:
    def __init__(self, n_img=3):
        self.n_img = n_img
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

    def create_yield_object(self, message, phase, status=True, data=None):
        return {'message': message, 'phase': phase, 'status': status, 'data': data}

    def get_fingerprint(self, operation):
        n = self.n_img
        if operation == 'verify':
            n = 2
        try:
            for finger_img in range(1, n + 1):
                # get fingerprint image
                yield self.create_yield_object("\nPlace finger on sensor...", FINGER_IMAGE_ACQUISITION)

                while True:
                    finger_image = self.finger.get_image()

                    if finger_image == adafruit_fingerprint.OK:
                        yield self.create_yield_object("Image taken\n", FINGER_IMAGE_ACQUISITION)
                        break

                    elif finger_image == adafruit_fingerprint.NOFINGER:
                        yield self.create_yield_object(".", FINGER_IMAGE_ACQUISITION)

                    elif finger_image == adafruit_fingerprint.IMAGEFAIL:
                        yield self.create_yield_object("Imaging error\n", FINGER_IMAGE_ACQUISITION, False)
                        return

                    else:
                        yield self.create_yield_object("Other error\n", FINGER_IMAGE_ACQUISITION, False)
                        return

                # Generate fingerprint template
                yield self.create_yield_object("Templating...", TEMPLATE_CREATION)
                template = self.finger.image_2_tz(finger_img)

                if template == adafruit_fingerprint.OK:
                    yield self.create_yield_object("Templated\n", TEMPLATE_CREATION)

                elif template == adafruit_fingerprint.IMAGEMESS:
                    yield self.create_yield_object("Image too messy\n", TEMPLATE_CREATION, False)
                    return

                elif template == adafruit_fingerprint.FEATUREFAIL:
                    yield self.create_yield_object("Could not identify features\n", TEMPLATE_CREATION, False)
                    return

                elif template == adafruit_fingerprint.INVALIDIMAGE:
                    yield self.create_yield_object("Image invalid\n", TEMPLATE_CREATION, False)
                    return

                else:
                    yield self.create_yield_object("Other error\n", TEMPLATE_CREATION, False)
                    return

                yield self.create_yield_object("Remove finger...", FINGER_REMOVAL)
                time.sleep(1)
                removal_status = None
                while removal_status != adafruit_fingerprint.NOFINGER:
                    removal_status = self.finger.get_image()
                    yield self.create_yield_object(".", FINGER_REMOVAL)

            # Model generation
            yield self.create_yield_object("\nCreating model...", MODEL_CREATION)
            model = self.finger.create_model()

            if model == adafruit_fingerprint.OK:
                yield self.create_yield_object("Model created\n", MODEL_CREATION)

            elif model == adafruit_fingerprint.ENROLLMISMATCH:
                yield self.create_yield_object("Prints did not match\n", MODEL_CREATION, False)
                return

            else:
                yield self.create_yield_object("Other error\n", MODEL_CREATION, False)
                return

            data = {'model_data': self.finger.get_fpdata("char", 1)}
            yield self.create_yield_object("", MODEL_DATA, data=data)

        except Exception as e:
            yield self.create_yield_object(f'{e}\n', ERROR, False)
            return
