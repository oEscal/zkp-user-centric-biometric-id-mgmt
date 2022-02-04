from statistics import mean
import numpy as np
import cv2
import pickle

FINGERPRINT_ERRORS = {
    'NOT_READY': "Error in sensor's initialization; Refresh the page to try again",
    'REGISTER_ERROR': "There was an error registering this user's fingerprint on the selected IdP.",
    'LOGIN_ERROR': "The IdP was no able to login with face"
}
TERMINATIONS_THRESHOLD = 80.0402578479092
BIFURCATIONS_THRESHOLD = 55.116784143566555
TERMINATIONS_VOTERS = 3
BIFURCATIONS_VOTERS = 1


class Fingerprint:
    def __init__(self, username, save_fingerprint_func=None, get_fingerprint_func=None):
        self.username = username
        self.save_fingerprint_func = save_fingerprint_func
        self.get_fingerprint_func = get_fingerprint_func

    def register_new_user(self, fingerprint_descriptors):
        if not self.save_fingerprint_func:
            raise NotImplementedError("Save fingerprint function does not exists")

        return self.save_fingerprint_func(self.username, fingerprint_descriptors)

    def __convert_binary_data_to_image(self, content):
        np_arr = np.fromstring(content, np.uint8)
        return cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    def __get_scores(self, descriptors_terminators, descriptors_bifurcations):
        desc_terminations1, desc_terminations2 = descriptors_terminators
        desc_bifurcations1, desc_bifurcations2 = descriptors_bifurcations

        matcher_terminations = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matcher_bifurcations = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)

        matches_terminations = sorted(matcher_terminations.match(desc_terminations1, desc_terminations2),
                                      key=lambda match: match.distance)
        matches_bifurcations = sorted(matcher_bifurcations.match(desc_bifurcations1, desc_bifurcations2),
                                      key=lambda match: match.distance)

        score_terminations = mean([match.distance for match in matches_terminations])
        score_bifurcations = mean([match.distance for match in matches_bifurcations])

        return score_terminations, score_bifurcations

    def verify_user(self, fingerprint_descriptors):
        if not self.get_fingerprint_func:
            raise NotImplementedError("Get fingerprint function does not exists")

        fingerprint_descriptors = pickle.loads(fingerprint_descriptors)
        if len(fingerprint_descriptors) == 0:
            raise Exception("Invalid descriptors")

        incoming_descriptor_terminations, incoming_descriptor_bifurcations = fingerprint_descriptors[0]
        saved_descriptors = pickle.loads(self.get_fingerprint_func(self.username))

        terminations_votes = 0
        bifurcations_votes = 0
        for descriptor in saved_descriptors:
            score_terminations, score_bifurcations = self.__get_scores(
                (descriptor[0], incoming_descriptor_terminations,),
                (descriptor[1], incoming_descriptor_bifurcations,)
            )

            terminations_votes += int(score_terminations <= TERMINATIONS_THRESHOLD)
            bifurcations_votes += int(score_bifurcations <= BIFURCATIONS_THRESHOLD)
            print(f'{score_terminations=}')
            print(f'{score_bifurcations=}')

        return terminations_votes >= TERMINATIONS_VOTERS and bifurcations_votes >= BIFURCATIONS_VOTERS
