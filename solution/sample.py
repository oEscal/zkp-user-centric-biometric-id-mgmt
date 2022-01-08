import os

import fingerprint_enhancer
import cv2
import fingerprint_feature_extractor
from statistics import mean
import matplotlib.pyplot as plt
import numpy as np


def get_key_points(features_terminations, features_bifurcations):
    key_points_terminations = []
    key_points_bifurcations = []

    for termination in features_terminations:
        x, y, orientation = termination.locX, termination.locY, termination.Orientation[0]
        key_points_terminations.append(cv2.KeyPoint(y, x, 1, angle=orientation))

    for bifurcation in features_bifurcations:
        x, y, orientation = bifurcation.locX, bifurcation.locY, bifurcation.Orientation
        a, b, c = orientation
        major_angle = max((a - b, b - c, c - a))
        key_points_bifurcations.append(cv2.KeyPoint(y, x, 1, angle=major_angle))

    return key_points_terminations, key_points_bifurcations


def generate_descriptors(image, kp_terminations, kp_bifurcations):
    orb_terminations = cv2.ORB_create()
    _, desc_terminations = orb_terminations.compute(image, kp_terminations)

    orb_bifurcations = cv2.ORB_create()
    _, desc_bifurcations = orb_bifurcations.compute(image, kp_bifurcations)

    return desc_terminations, desc_bifurcations


def plot_data(img1, img2, kp1, kp2, matches_terminations, matches_bifurcations):
    kp_terminations1, kp_bifurcations1 = kp1
    kp_terminations2, kp_bifurcations2 = kp2

    plot_img_terminations_1 = cv2.drawKeypoints(img1, kp_terminations1, outImage=None)
    plot_img_bifurcations_1 = cv2.drawKeypoints(img1, kp_bifurcations1, outImage=None)
    plot_img_terminations_2 = cv2.drawKeypoints(img2, kp_terminations2, outImage=None)
    plot_img_bifurcations_2 = cv2.drawKeypoints(img2, kp_bifurcations2, outImage=None)

    f, ax_array = plt.subplots(2, 2)
    ax_array[0][0].imshow(plot_img_terminations_1)
    ax_array[0][1].imshow(plot_img_terminations_2)

    ax_array[1][0].imshow(plot_img_bifurcations_1)
    ax_array[1][1].imshow(plot_img_bifurcations_2)

    plt.show()

    f, ax_array = plt.subplots(1, 2)

    img_terminations_matches = cv2.drawMatches(img1, kp_terminations1, img2, kp_terminations2, matches_terminations,
                                               flags=2, outImg=None)
    img_bifurcations_matches = cv2.drawMatches(img1, kp_bifurcations1, img2, kp_bifurcations2, matches_bifurcations,
                                               flags=2, outImg=None)

    ax_array[0].imshow(img_terminations_matches)
    ax_array[1].imshow(img_bifurcations_matches)

    plt.show()


def extract_features(out):
    features_terminations, features_bifurcations = fingerprint_feature_extractor.extract_minutiae_features(out)
    return features_terminations, features_bifurcations


def enhance_image(img):
    out = fingerprint_enhancer.enhance_Fingerprint(img)
    return out


def get_scores(descriptors_terminators, descriptors_bifurcations):
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

    return score_terminations, score_bifurcations, matches_terminations, matches_bifurcations


def is_match(saved_descriptors, actual_descriptor, terminations_threshold, bifurcations_threshold):
    for descriptor in saved_descriptors:
        score_terminations, score_bifurcations, _, _ = get_scores(
            (descriptor[0], actual_descriptor[0],),
            (descriptor[1], actual_descriptor[1],)
        )
        if score_terminations < terminations_threshold and score_bifurcations < bifurcations_threshold:
            return True
    return False


def overall_image_quality(img):
    w, h = img.shape
    non_zeros = np.count_nonzero(img == 0)
    return non_zeros / (w * h)


def main():
    """
    FSRCNN_x2.pb
        score_terminations=61.5
        score_bifurcations=46.65853658536585
        0.14721989631652832
    """
    sr = cv2.dnn_superres.DnnSuperResImpl_create()
    sr.readModel('FSRCNN_x2.pb')
    sr.setModel("fsrcnn", 2)

    images = os.listdir('fingerprints')
    img1 = images[0]
    img2 = images[1]

    print(img1)
    img1 = cv2.imread(f'fingerprints/{img1}', 0)
    img1 = enhance_image(img1)
    print(overall_image_quality(img1))
    exit()
    img2 = cv2.imread(f'fingerprints/{img2}', 1)

    img1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
    img2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)

    out1 = enhance_image(img1)
    out2 = enhance_image(img2)

    features_terminations1, features_bifurcations1 = extract_features(out1)
    features_terminations2, features_bifurcations2 = extract_features(out2)

    kp_terminations1, kp_bifurcations1 = get_key_points(features_terminations1, features_bifurcations1)
    kp_terminations2, kp_bifurcations2 = get_key_points(features_terminations2, features_bifurcations2)

    desc_terminations1, desc_bifurcations1 = generate_descriptors(out1, kp_terminations1, kp_bifurcations1)
    desc_terminations2, desc_bifurcations2 = generate_descriptors(out2, kp_terminations2, kp_bifurcations2)

    score_terminations, score_bifurcations, matches_terminations, matches_bifurcations = get_scores(
        (desc_terminations1, desc_terminations2,),
        (desc_bifurcations1, desc_bifurcations2,)
    )

    print(f'{score_terminations=}')
    print(f'{score_bifurcations=}')

    # plot_data(out1, out2, (kp_terminations1, kp_bifurcations1,), (kp_terminations2, kp_bifurcations2,),
    #           matches_terminations, matches_bifurcations)


if __name__ == '__main__':
    main()
