from fingerprint_enhancer import enhance_Fingerprint
from skimage.morphology import skeletonize, thin
from statistics import mean
import numpy as np
import cv2

FINGERPRINT_ERRORS = {
    'NOT_READY': "Error in sensor's initialization; Refresh the page to try again",
    'REGISTER_ERROR': "There was an error registering this user's fingerprint on the selected IdP.",
    'LOGIN_ERROR': "The IdP was no able to login with face"
}

SCORE_THRESHOLD = 21


class Fingerprint:
    def __init__(self, username, save_fingerprint_func=None, get_fingerprint_func=None):
        self.username = username
        self.save_fingerprint_func = save_fingerprint_func
        self.get_fingerprint_func = get_fingerprint_func

    def register_new_user(self, fingerprint_image):
        if not self.save_fingerprint_func:
            raise NotImplementedError("Save fingerprint function does not exists")
        return self.save_fingerprint_func(self.username, fingerprint_image)

    def __removedot(self, invert_thin):
        temp0 = np.array(invert_thin[:])
        temp0 = np.array(temp0)
        temp1 = temp0 / 255
        temp2 = np.array(temp1)

        w, h = temp0.shape[:2]
        filter_size = 6

        for i in range(w - filter_size):
            for j in range(h - filter_size):
                filter0 = temp1[i:i + filter_size, j:j + filter_size]

                flag = 0
                if sum(filter0[:, 0]) == 0:
                    flag += 1
                if sum(filter0[:, filter_size - 1]) == 0:
                    flag += 1
                if sum(filter0[0, :]) == 0:
                    flag += 1
                if sum(filter0[filter_size - 1, :]) == 0:
                    flag += 1
                if flag > 3:
                    temp2[i:i + filter_size, j:j + filter_size] = np.zeros((filter_size, filter_size))

        return temp2

    def __get_descriptors(self, img):
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        img = clahe.apply(img)
        img = enhance_Fingerprint(img)
        img = np.array(img, dtype=np.uint8)
        # Threshold
        ret, img = cv2.threshold(img, 127, 255, cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)
        # Normalize to 0 and 1 range
        img[img == 255] = 1

        # Thinning
        skeleton = skeletonize(img)
        skeleton = np.array(skeleton, dtype=np.uint8)
        skeleton = self.__removedot(skeleton)
        # Harris corners
        harris_corners = cv2.cornerHarris(img, 3, 3, 0.04)
        harris_normalized = cv2.normalize(harris_corners, 0, 255, norm_type=cv2.NORM_MINMAX, dtype=cv2.CV_32FC1)
        threshold_harris = 125
        # Extract key_points
        key_points = []
        for x in range(0, harris_normalized.shape[0]):
            for y in range(0, harris_normalized.shape[1]):
                if harris_normalized[x][y] > threshold_harris:
                    key_points.append(cv2.KeyPoint(y, x, 1))
        # Define descriptor
        orb = cv2.ORB_create()
        # Compute descriptors
        _, des = orb.compute(img, key_points)
        return key_points, des

    def __convert_bytes_to_numpy_array(self, content):
        np_arr = np.fromstring(content, np.uint8)
        return cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)

    def verify_user(self, fingerprint_image):
        if not self.get_fingerprint_func:
            raise NotImplementedError("Get fingerprint function does not exists")

        saved_fingerprint_image = self.__convert_bytes_to_numpy_array(self.get_fingerprint_func(self.username))
        incoming_fingerprint_image = self.__convert_bytes_to_numpy_array(fingerprint_image)

        saved_kp, saved_des = self.__get_descriptors(saved_fingerprint_image)
        incoming_kp, incoming_des = self.__get_descriptors(incoming_fingerprint_image)

        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = sorted(bf.match(saved_des, incoming_des), key=lambda match: match.distance)

        mean_score = mean([match.distance for match in matches])
        print(mean_score)
        return mean_score < SCORE_THRESHOLD
