import fingerprint_enhancer
import cv2
import fingerprint_feature_extractor
from statistics import mean
import matplotlib.pyplot as plt


def get_key_points(features_terminations, features_bifurcations):
    key_points_bifurcations = []
    key_points_terminations = []
    for bifurcation in features_bifurcations:
        x, y, orientation = bifurcation.locX, bifurcation.locY, bifurcation.Orientation
        a, b, c = orientation
        major_angle = max((a - b, b - c, c - a))
        key_points_bifurcations.append(cv2.KeyPoint(y, x, 1, angle=major_angle))

    for termination in features_terminations:
        x, y, orientation = termination.locX, termination.locY, termination.Orientation[0]
        key_points_terminations.append(cv2.KeyPoint(y, x, 1, angle=orientation))

    return key_points_terminations, key_points_bifurcations


def generate_descriptors(image, kp_terminations, kp_bifurcations):
    orb_bifurcations = cv2.ORB_create()
    _, desc_bifurcations = orb_bifurcations.compute(image, kp_bifurcations)

    orb_terminations = cv2.ORB_create()
    _, desc_terminations = orb_terminations.compute(image, kp_terminations)

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


def main():
    img1 = cv2.imread('enroll_1.png', 0)
    img2 = cv2.imread('enroll_3.png', 0)

    out1 = fingerprint_enhancer.enhance_Fingerprint(img1)
    out2 = fingerprint_enhancer.enhance_Fingerprint(img2)

    features_terminations1, features_bifurcations1 = fingerprint_feature_extractor.extract_minutiae_features(out1)
    features_terminations2, features_bifurcations2 = fingerprint_feature_extractor.extract_minutiae_features(out2)

    kp_terminations1, kp_bifurcations1 = get_key_points(features_terminations1, features_bifurcations1)
    kp_terminations2, kp_bifurcations2 = get_key_points(features_terminations2, features_bifurcations2)

    desc_terminations1, desc_bifurcations1 = generate_descriptors(out1, kp_terminations1, kp_bifurcations1)
    desc_terminations2, desc_bifurcations2 = generate_descriptors(out2, kp_terminations2, kp_bifurcations2)

    matcher_terminations = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matcher_bifurcations = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)

    matches_terminations = sorted(matcher_terminations.match(desc_terminations1, desc_terminations2),
                                  key=lambda match: match.distance)
    matches_bifurcations = sorted(matcher_bifurcations.match(desc_bifurcations1, desc_bifurcations2),
                                  key=lambda match: match.distance)

    score_terminations = mean([match.distance for match in matches_terminations])
    score_bifurcations = mean([match.distance for match in matches_bifurcations])

    print(f'{score_terminations=}')
    print(f'{score_bifurcations=}')

    # plot_data(img1, img2, (kp_terminations1, kp_bifurcations1,), (kp_terminations2, kp_bifurcations2,),
    #           matches_terminations, matches_bifurcations)


if __name__ == '__main__':
    main()