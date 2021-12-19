from statistics import mean
import numpy as np
import cv2
import pickle

FINGERPRINT_ERRORS = {
    'NOT_READY': "Error in sensor's initialization; Refresh the page to try again",
    'REGISTER_ERROR': "There was an error registering this user's fingerprint on the selected IdP.",
    'LOGIN_ERROR': "The IdP was no able to login with face"
}
TERMINATIONS_THRESHOLD = 25
BIFURCATIONS_THRESHOLD = 25


# SCORE_THRESHOLD = 25


class Fingerprint:
    def __init__(self, username, save_fingerprint_func=None, get_fingerprint_func=None):
        self.username = username
        self.save_fingerprint_func = save_fingerprint_func
        self.get_fingerprint_func = get_fingerprint_func

    def register_new_user(self, fingerprint_descriptors):
        if not self.save_fingerprint_func:
            raise NotImplementedError("Save fingerprint function does not exists")

        return self.save_fingerprint_func(self.username, fingerprint_descriptors)

    def __convert_bytes_to_numpy_array(self, content):
        np_arr = np.fromstring(content, np.uint8)
        return cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)

    def verify_user(self, fingerprint_descriptors):
        if not self.get_fingerprint_func:
            raise NotImplementedError("Get fingerprint function does not exists")

        incoming_descriptor_terminations, incoming_descriptor_bifurcations = pickle.loads(fingerprint_descriptors)
        saved_descriptor_terminations, saved_descriptor_bifurcations = pickle.loads(
            self.get_fingerprint_func(self.username))

        terminations_matcher = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        terminations_matches = sorted(
            terminations_matcher.match(saved_descriptor_terminations, incoming_descriptor_terminations),
            key=lambda match: match.distance)

        bifurcations_matcher = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        bifurcations_matches = sorted(
            bifurcations_matcher.match(saved_descriptor_bifurcations, incoming_descriptor_bifurcations),
            key=lambda match: match.distance)

        terminations_mean_score = mean([match.distance for match in terminations_matches])
        bifurcations_mean_score = mean([match.distance for match in bifurcations_matches])

        print(terminations_mean_score, bifurcations_mean_score)
        return terminations_mean_score < TERMINATIONS_THRESHOLD and bifurcations_mean_score < BIFURCATIONS_THRESHOLD
