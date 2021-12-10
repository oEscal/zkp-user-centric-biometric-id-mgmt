import adafruit_fingerprint
import serial
import time
import io
from PIL import Image

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
    def __init__(self, n_img=10):
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

            msg = "\nCreating fingerprint model...\n"
            if operation == 'verify':
                msg = "\nChecking fingerprint model...\n"
            yield self.create_yield_object(msg, MODEL_CREATION)
            data = {'model_data': self.finger.get_fpdata("image")}
            yield self.create_yield_object("", MODEL_DATA, data=data)

        except Exception as e:
            yield self.create_yield_object(f'{e}\n', ERROR, False)
            return

    def convert_model_data_to_image(self, model_data):
        try:
            img = Image.new("L", (256, 288), "white")
            pixel_data = img.load()
            mask = 0b00001111

            x, y = 0, 0
            for i in range(len(model_data)):
                pixel_data[x, y] = (int(model_data[i]) >> 4) * 17
                x += 1
                pixel_data[x, y] = (int(model_data[i]) & mask) * 17
                if x == 255:
                    x = 0
                    y += 1
                else:
                    x += 1

            buf = io.BytesIO()
            img.save(buf, format='PNG')
            return buf.getvalue()

        except Exception as e:
            print(f'Error {e}')
            return None
