import json

from scipy.optimize import differential_evolution
from sklearn.metrics import matthews_corrcoef, confusion_matrix
from sample import extract_features, get_key_points, generate_descriptors, is_match, enhance_image
import multiprocessing as mp
import numpy as np
import os
import cv2
import functools

DATA_PATH = 'fingerprints_upscaled'


def get_params_from_filename(file_name):
    image_index, name, side, finger_id, acquisition_time = file_name.split('_')
    return int(image_index), name, side, int(finger_id), int(acquisition_time.split('.')[0])


def generate_images_descriptors(images):
    descriptors = {}
    for img in images:
        full_path = f'{DATA_PATH}/{img}'

        image = cv2.imread(full_path, 0)
        enhanced_image = enhance_image(image)
        features_terminations, features_bifurcations = extract_features(enhanced_image)
        kp_terminations, kp_bifurcations = get_key_points(features_terminations, features_bifurcations)
        desc_terminations, desc_bifurcations = generate_descriptors(enhanced_image, kp_terminations, kp_bifurcations)
        descriptors[img] = (desc_terminations, desc_bifurcations,)

    return descriptors


def score_function(parameters, descriptors, descriptors_grouped_by_name, generate_confusion_matrix=False):
    terminations_threshold, bifurcations_threshold = parameters
    y_true = []
    y_pred = []
    images = list(descriptors.keys())
    for i in range(len(images)):
        for j in range(i + 1, len(images)):
            # desc_terminations1, desc_bifurcations1 = descriptors[images[i]]
            desc_terminations2, desc_bifurcations2 = descriptors[images[j]]

            params1, params2 = get_params_from_filename(images[i]), get_params_from_filename(images[j])

            if params1[1:-1] == params2[1:-1]:
                y_true.append(1)
            else:
                y_true.append(-1)

            this_descriptors = [descriptors[x] for x in descriptors_grouped_by_name[params1[1:-1]] if x != images[j]]
            prediction = int(is_match(this_descriptors, (desc_terminations2, desc_bifurcations2),
                                      terminations_threshold, bifurcations_threshold))
            if prediction == 0:
                prediction = -1
            y_pred.append(prediction)

    if generate_confusion_matrix:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        with open('confusion_matrix.log', 'a') as f:
            f.write(f'{tn=} {fp=} {fn=} {tp=}\n')

    return 1 - matthews_corrcoef(y_true, y_pred)


def cb(descriptors, descriptors_grouped_by_name, x, convergence):
    terminations_threshold, bifurcations_threshold = x
    print(f"{terminations_threshold=}")
    print(f"{bifurcations_threshold=}")
    score_function(x, descriptors, descriptors_grouped_by_name, True)


def main():
    images = os.listdir(DATA_PATH)
    images = [x for x in images]
    print(len(images))

    n_process = mp.cpu_count()
    pool = mp.Pool(processes=n_process)

    results = [pool.apply_async(generate_images_descriptors, args=(sub_images,)) for sub_images in
               np.array_split(images, n_process)]
    results = [p.get() for p in results]
    descriptors = {k: v for x in results for k, v in x.items()}
    descriptors_grouped_by_name = {}

    for img in descriptors:
        params = get_params_from_filename(img)[1:-1]
        if params not in descriptors_grouped_by_name:
            descriptors_grouped_by_name[params] = []

        descriptors_grouped_by_name[params].append(img)

    bounds = [(0, 100)] * 2

    cb_partial = functools.partial(cb, descriptors, descriptors_grouped_by_name)
    optimizer = differential_evolution(func=score_function, bounds=bounds,
                                       args=(descriptors, descriptors_grouped_by_name), workers=n_process,
                                       disp=True, maxiter=100, tol=0, callback=cb_partial)

    with open('thresholds.json', 'w') as fp:
        json.dump({
            'x': optimizer.x.tolist(),
            'fun': optimizer.fun.tolist()
        }, fp)


if __name__ == '__main__':
    main()
