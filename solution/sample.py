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
        key_points_terminations.append(cv2.KeyPoint(y, x, 1, orientation))

    for bifurcation in features_bifurcations:
        x, y, orientation = bifurcation.locX, bifurcation.locY, bifurcation.Orientation
        a, b, c = orientation
        major_angle = max((a - b, b - c, c - a))
        key_points_bifurcations.append(cv2.KeyPoint(y, x, 1, major_angle))

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


def extract_features(out, spurious_minutiae_thresh=10):
    features_terminations, features_bifurcations = fingerprint_feature_extractor.extract_minutiae_features(out,
                                                                                                           spuriousMinutiaeThresh=spurious_minutiae_thresh)
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


import shutil
import multiprocessing as mp
import numpy as np


def function(images):
    for img_path in images:
        print(img_path)
        full_path = f'fingerprints_upscaled/{img_path}'
        img = cv2.imread(full_path, 0)
        out = enhance_image(img)
        if overall_image_quality(out) <= 0.725:
            shutil.copyfile(full_path, f'fingerprints_good/{img_path}')
        else:
            shutil.copyfile(full_path, f'fingerprints_bad/{img_path}')


def main():
    """
    pool = mp.Pool(8)
    # fingerprints_good/
    # fingerprints_bad/
    results = [pool.apply_async(function, args=(sub_images,)) for sub_images in
               np.array_split(os.listdir('fingerprints_upscaled'), 8)]
    results = [p.get() for p in results]

    exit()
    """
    images = os.listdir('fingerprints_upscaled')
    img1 = images[0]
    img2 = images[1]
    print(img1, img2)

    img1 = cv2.imread(f'fingerprints/1_rafael_l_5_1640623577.png', 0)
    img2 = cv2.imread(f'fingerprints/1_rafael_l_5_1640623025.png', 0)

    out1 = enhance_image(img1)
    out2 = enhance_image(img2)

    print(overall_image_quality(out1))
    print(overall_image_quality(out2))

    exit()
    features_terminations1, features_bifurcations1 = extract_features(img1)
    features_terminations2, features_bifurcations2 = extract_features(img2)

    a, b = len(features_terminations1), len(features_bifurcations1)
    c, d = len(features_terminations2), len(features_bifurcations2)
    print(a, b, a + b)
    print(c, d, c + d)

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

    plot_data(out1, out2, (kp_terminations1, kp_bifurcations1,), (kp_terminations2, kp_bifurcations2,),
              matches_terminations, matches_bifurcations)


if __name__ == '__main__':
    main()
