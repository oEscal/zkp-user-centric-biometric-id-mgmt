import time

import adafruit_fingerprint
import serial
import cv2
import numpy as np
import io
import multiprocessing as mp
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
VALID_IMAGE = 8
ALL_IMAGES_VALID = 9


class Fingerprint:
    def __init__(self, n_img=10, scans_per_image=10, n_processes=5):
        self.n_img = n_img
        self.scans_per_image = scans_per_image
        self.uart = None
        self.finger = None
        self.img_buffer = []
        self.n_processes = n_processes

    def setup(self):
        try:
            self.uart = serial.Serial("/dev/ttyUSB0", baudrate=57600, timeout=1)
            self.finger = adafruit_fingerprint.Adafruit_Fingerprint(self.uart)
            return {'is_ready': True, 'message': None}
        except Exception as e:
            print(e)
            return {'is_ready': False, 'message': FINGERPRINT_ERRORS['NOT_READY']}

    def clear_buffer(self):
        self.img_buffer = []

    def create_yield_object(self, message, phase, status=True, data=None):
        return {'message': message, 'phase': phase, 'status': status, 'data': data}

    def get_fingerprint(self, operation, name, side, index_finger):
        self.img_buffer = []
        n = self.n_img
        if operation == 'verify':
            n = 1
        try:
            start_time = int(time.time())
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

                yield self.create_yield_object("Remove the finger\n", FINGER_IMAGE_ACQUISITION)

                yield self.create_yield_object("\nGenerating image...\n", IMAGE_GENERATION)

                image_binary = self.convert_model_data_to_image(self.finger.get_fpdata("image"))
                image = self.__convert_binary_data_to_image(image_binary)

                yield self.create_yield_object("", IMAGE_DATA, data=image_binary)

                validation_status = self.valid_image(image, self.img_buffer)
                if not validation_status.get('is_good'):
                    yield self.create_yield_object("\nThis image has a low quality\nTry again...\n",
                                                   LOW_QUALITY_IMAGE)
                    continue

                if not validation_status.get('is_different'):
                    yield self.create_yield_object(
                        "\nThis image is not different enough from the remaining\nTry again...\n",
                        SIMILAR_IMAGE)
                    continue

                self.img_buffer.append(image)
                with open(f'fingerprints_database/fingerprints_class/{finger_img}_{name}_{side}_{index_finger}_{start_time}.png', 'wb') as fp:
                    fp.write(image_binary)

                finger_img += 1
                yield self.create_yield_object("\nValid image\n", VALID_IMAGE)

            yield self.create_yield_object("\nAll images taken\n", ALL_IMAGES_VALID)

        except Exception as e:
            yield self.create_yield_object(f'{e}\n', ERROR, False)
            return

    def valid_image(self, current_image, other_images, difference_threshold=0.60, quality_threshold=0.7):
        return {'is_different': self.__is_different_enough(current_image, other_images, difference_threshold),
                'is_good': self.__is_good_enough(current_image, quality_threshold)}

    def __convert_binary_data_to_image(self, binary_data):
        return cv2.imdecode(np.fromstring(binary_data, np.uint8), cv2.IMREAD_COLOR)

    def __crop_image(self, img):
        indices = np.argwhere(img == 255)
        x_list, y_list = [e[1] for e in indices], [e[0] for e in indices]

        min_x, min_y = min(x_list), min(y_list)
        max_x, max_y = max(x_list), max(y_list)

        x, y, w, h = min_x, min_y, max_x - min_x, max_y - min_y

        cropped_imd = img[y:y + h, x:x + w]
        return cropped_imd

    def __is_different_enough(self, current_image, other_images, difference_threshold):
        for img in other_images:
            res = cv2.absdiff(current_image, img)
            res = res.astype(np.uint8)

            difference_score = np.count_nonzero(res) / res.size
            print(f"{difference_score=}")
            if difference_score < difference_threshold:
                return False

        return True

    def __is_good_enough(self, img, quality_threshold):
        img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        image = self._enhance_image(img)
        image = self.__crop_image(image)
        w, h = image.shape
        non_zeros = np.count_nonzero(image == 0)
        quality_score = non_zeros / (w * h)
        print(f"{quality_score=}")
        return quality_score <= quality_threshold

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

    def _enhance_image(self, img):
        out = enhance_Fingerprint(img)
        return out

    def _generate_key_points(self, features_terminations, features_bifurcations):
        key_points_terminations = []
        key_points_bifurcations = []

        for termination in features_terminations:
            x, y, angle = termination.locX, termination.locY, termination.Orientation[0]
            key_points_terminations.append(cv2.KeyPoint(y, x, 1, angle=angle))

        for bifurcation in features_bifurcations:
            x, y, orientation = bifurcation.locX, bifurcation.locY, bifurcation.Orientation
            a, b, c = orientation
            major_angle = max((a - b, b - c, c - a))
            key_points_bifurcations.append(cv2.KeyPoint(y, x, 1, angle=major_angle))

        return key_points_terminations, key_points_bifurcations

    def _generate_descriptors(self, image, kp_terminations, kp_bifurcations):
        orb_terminations = cv2.ORB_create()
        _, desc_terminations = orb_terminations.compute(image, kp_terminations)

        orb_bifurcations = cv2.ORB_create()
        _, desc_bifurcations = orb_bifurcations.compute(image, kp_bifurcations)

        return desc_terminations, desc_bifurcations

    def _descriptors_generation_workflow(self, img):
        out = self._enhance_image(img)
        features_terminations, features_bifurcations = extract_minutiae_features(out)
        kp_terminations, kp_bifurcations = self._generate_key_points(features_terminations, features_bifurcations)
        desc_terminations, desc_bifurcations = self._generate_descriptors(out, kp_terminations, kp_bifurcations)

        return desc_terminations, desc_bifurcations

    def get_descriptors(self, pickled=True):
        if len(self.img_buffer) == 0:
            return None

        pool = mp.Pool(processes=self.n_processes)
        descriptors = [pool.apply_async(self._descriptors_generation_workflow, args=(img,)) for img in self.img_buffer]
        descriptors = [p.get() for p in descriptors]
        pool.close()
        pool.join()
        self.clear_buffer()

        if pickled:
            return pickle.dumps(descriptors)

        return descriptors
