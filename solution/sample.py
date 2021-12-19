import fingerprint_enhancer
import cv2
import fingerprint_feature_extractor
import numpy as np
from skimage.morphology import skeletonize, thin
from statistics import mean
import matplotlib.pyplot as plt

img = cv2.imread('2.png', 0)
out = fingerprint_enhancer.enhance_Fingerprint(img)

FeaturesTerminations, FeaturesBifurcations = fingerprint_feature_extractor.extract_minutiae_features(img,
                                                                                                     showResult=False,
                                                                                                     spuriousMinutiaeThresh=10)

print(FeaturesTerminations[0].__dict__)
print(FeaturesBifurcations[0].__dict__)
key_points = []
for termination in FeaturesBifurcations:
    x, y, orientation = termination.locX, termination.locY, termination.Orientation
    key_points.append(cv2.KeyPoint(y, x, 1))

orb = cv2.ORB_create()
# Compute descriptors
_, des = orb.compute(img, key_points)

bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
matches = sorted(bf.match(des, des), key=lambda match: match.distance)

mean_score = mean([match.distance for match in matches])

print(mean_score)


img4 = cv2.drawKeypoints(img, key_points, outImage=None)
img5 = cv2.drawKeypoints(img, key_points, outImage=None)
f, axarr = plt.subplots(1, 2)
axarr[0].imshow(img4)
axarr[1].imshow(img5)
plt.show()
# Plot matches
img3 = cv2.drawMatches(img, key_points, img, key_points, matches, flags=2, outImg=None)
plt.imshow(img3)
plt.show()

exit()
print(FeaturesTerminations[0].__dict__)
print(FeaturesBifurcations[0].__dict__)

exit()
img = np.array(out, dtype=np.uint8)
# Threshold
ret, img = cv2.threshold(img, 127, 255, cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)
# Normalize to 0 and 1 range
img[img == 255] = 1

# Thinning
skeleton = skeletonize(img)
skeleton = np.array(skeleton, dtype=np.uint8)
# Harris corners
harris_corners = cv2.cornerHarris(img, 3, 3, 0.04)
harris_normalized = cv2.normalize(harris_corners, 0, 255, norm_type=cv2.NORM_MINMAX, dtype=cv2.CV_32FC1)
threshold_harris = 125
# Extract key_points
key_points = []
for x in range(0, harris_normalized.shape[0]):
    for y in range(0, harris_normalized.shape[1]):
        print(harris_normalized[x][y])
        if harris_normalized[x][y] > threshold_harris:
            key_points.append(cv2.KeyPoint(y, x, 1))
# Define descriptor
orb = cv2.ORB_create()
# Compute descriptors
_, des = orb.compute(img, key_points)
