import adafruit_fingerprint
import serial
import cv2
import numpy as np
import io
import pickle
from PIL import Image
from fingerprint_enhancer import enhance_Fingerprint
from fingerprint_feature_extractor import extract_minutiae_features

FINGERPRINT_ERRORS = {
    'NOT_READY': "Error in sensor's initialization; Refresh the page to try again",
    'REGISTER_ERROR': "There was an error registering this user's fingerprint on the selected IdP.",
    'LOGIN_ERROR': "The IdP was no able to login with fingerprint",
    'DESCRIPTORS_ERROR': "Error in descriptors generation"
}

FINGER_IMAGE_ACQUISITION = 0
TEMPLATE_CREATION = 1
FINGER_REMOVAL = 2
IMAGE_GENERATION = 3
IMAGE_DATA = 4
ERROR = 5
LOW_QUALITY_IMAGE = 6
SIMILAR_IMAGE = 7


# IMAGE_DIFFERENCE = 6
# # descriptors
# DESCRIPTORS_GENERATION = 7
# DESCRIPTORS_DATA = 8


class Fingerprint:
    def __init__(self, n_img=3, scans_per_image=10):
        self.n_img = n_img
        self.scans_per_image = scans_per_image
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
        images_taken = []
        n = self.n_img
        if operation == 'verify':
            n = 1
        try:
            yield self.create_yield_object(f"You will be asked to get {n} fingerprint scans in different positions\n",
                                           FINGER_IMAGE_ACQUISITION)
            finger_img = 1
            while finger_img < (n + 1):
                # get fingerprint image
                yield self.create_yield_object(f"\nPlace finger on sensor ({finger_img})\n", FINGER_IMAGE_ACQUISITION)

                scan_count = 0
                while scan_count < self.scans_per_image:
                    finger_image = self.finger.get_image()

                    if finger_image == adafruit_fingerprint.OK:
                        yield self.create_yield_object(f"Image taken (Scan {scan_count + 1})\n",
                                                       FINGER_IMAGE_ACQUISITION)
                        scan_count += 1

                    elif finger_image == adafruit_fingerprint.NOFINGER:
                        yield self.create_yield_object(".", FINGER_IMAGE_ACQUISITION)

                    else:
                        yield self.create_yield_object("Internal error\n", FINGER_IMAGE_ACQUISITION, False)

                self.create_yield_object("Remove the finger\n", FINGER_IMAGE_ACQUISITION)

                yield self.create_yield_object("\nGenerating image...\n", IMAGE_GENERATION)

                image_binary = self.convert_model_data_to_image(self.finger.get_fpdata("image"))
                image = self.__convert_binary_data_to_image(image_binary)

                yield self.create_yield_object("", IMAGE_DATA, data=image_binary)

                if operation == 'register':
                    validation_status = self.valid_image(image, images_taken)
                    if not validation_status.get('is_good'):
                        yield self.create_yield_object("\nThis image has a low quality\nTry again...\n",
                                                       LOW_QUALITY_IMAGE)
                        continue

                    if not validation_status.get('is_different'):
                        yield self.create_yield_object(
                            "\nThis image is not different enough from the remaining\nTry again...\n",
                            SIMILAR_IMAGE)
                        continue

                images_taken.append(image)
                finger_img += 1
                
            pass
            """

        yield self.create_yield_object("\nGenerating fingerprint descriptors\n", DESCRIPTORS_GENERATION)
        descriptors = [
            self.get_descriptors(img) for img in taken_images
        ]
        yield self.create_yield_object("", DESCRIPTORS_DATA, data=descriptors)
        """

    except Exception as e:
    yield self.create_yield_object(f'{e}\n', ERROR, False)
    return


def valid_image(self, current_image, other_images, difference_threshold=0.7, quality_threshold=0.75):
    return {'is_different': self.__is_different_enough(current_image, other_images, difference_threshold),
            'is_good': self.__is_good_enough(current_image, quality_threshold)}


def __convert_binary_data_to_image(self, binary_data):
    return cv2.imdecode(np.fromstring(binary_data, np.uint8), 0)


def __is_different_enough(self, current_image, other_images, difference_threshold):
    for img in other_images:
        res = cv2.absdiff(current_image, img)
        res = res.astype(np.uint8)

        if np.count_nonzero(res) / res.size < difference_threshold:
            return False

    return True


def __is_good_enough(self, img, quality_threshold):
    image = self.__enhance_image(img)
    w, h = image.shape
    non_zeros = np.count_nonzero(image == 0)
    return non_zeros / (w * h) <= quality_threshold


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


def __convert_bytes_to_numpy_array(self, content):
    np_arr = np.fromstring(content, np.uint8)
    return cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)


def __enhance_image(self, img):
    out = enhance_Fingerprint(img)
    return out


def __generate_key_points(self, fingerprint_features):
    features_terminations, features_bifurcations = fingerprint_features
    kp_terminations, kp_bifurcations = [], []

    for entry in features_terminations:
        x, y = entry.locX, entry.locY
        kp_terminations.append(cv2.KeyPoint(y, x, 1))
    for entry in features_bifurcations:
        x, y = entry.locX, entry.locY
        kp_bifurcations.append(cv2.KeyPoint(y, x, 1))

    return kp_terminations, kp_bifurcations


def __create_descriptor(self, image, key_points):
    orb = cv2.ORB_create()
    _, descriptor = orb.compute(image, key_points)
    return descriptor


def get_descriptors(self, img_content, pickled=True):
    image = enhance_Fingerprint(self.__convert_bytes_to_numpy_array(img_content))
    kp_terminations, kp_bifurcations = self.__generate_key_points(
        extract_minutiae_features(image, spuriousMinutiaeThresh=10))

    descriptor_terminations = self.__create_descriptor(image, kp_terminations)
    descriptor_bifurcations = self.__create_descriptor(image, kp_bifurcations)

    if pickled:
        return pickle.dumps((descriptor_terminations, descriptor_bifurcations))

    return descriptor_terminations, descriptor_bifurcations
