import json
import random
import time
import math
import argparse
from pathlib import Path
from scipy.optimize import differential_evolution
from sklearn.metrics import matthews_corrcoef, confusion_matrix, accuracy_score
from sample import extract_features, get_key_points, generate_descriptors, get_matching_score, enhance_image
import multiprocessing as mp
import numpy as np
import os
import cv2
import statistics
import functools
import pickle

LOGS_DIR = "logs/fingerprint"
DESCRIPTORS_DB = 'descriptors_database'
voting_size = 10
START = time.time()


def voting(scores_terminations, scores_bifurcations, tolerance_terminations, tolerance_bifurcations):
    voting_favor_terminations, voting_favor_bifurcations = 0, 0
    for score_termination in scores_terminations:
        voting_favor_terminations += int(score_termination <= tolerance_terminations)

    for score_bifurcations in scores_bifurcations:
        voting_favor_bifurcations += int(score_bifurcations <= tolerance_bifurcations)

    return voting_favor_terminations, voting_favor_bifurcations


DECISIONS = {
    'mean': lambda a, b: (statistics.mean(a), statistics.mean(b),),
    'max': lambda a, b: (max(a), max(b),),
    'min': lambda a, b: (min(a), min(b),),
    'voting': voting
}


def save_scores_per_iteration(decision, name, data):
    def np_encoder(object):
        if isinstance(object, np.generic):
            return object.item()

    file_path = f'{LOGS_DIR}/scores_{name}_{START}_{decision}.json'
    if not os.path.isfile(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)

    with open(file_path, 'r') as f:
        content = json.load(f) + [data]

    with open(file_path, 'w') as f:
        json.dump(content, f, default=np_encoder)


def get_params_from_filename(file_name):
    image_index, name, side, finger_id, acquisition_time = file_name.split('_')
    return int(image_index), name, side, int(finger_id), int(acquisition_time.split('.')[0])


def generate_images_descriptors(images, data_path, descriptors_saved):
    descriptors = {}
    for img in images:
        full_path = f'{data_path}/{img}'
        descriptor_filename = full_path.replace('/', '_').split('.')[0]

        if descriptor_filename not in descriptors_saved:
            image = cv2.imread(full_path, 0)
            enhanced_image = enhance_image(image)
            features_terminations, features_bifurcations = extract_features(enhanced_image)
            kp_terminations, kp_bifurcations = get_key_points(features_terminations, features_bifurcations)
            desc_terminations, desc_bifurcations = generate_descriptors(enhanced_image, kp_terminations,
                                                                        kp_bifurcations)
            descriptors[img] = (desc_terminations, desc_bifurcations,)
            with open(f'{DESCRIPTORS_DB}/{descriptor_filename}', 'wb') as f:
                pickle.dump((desc_terminations, desc_bifurcations,), f)

        else:
            with open(f'{DESCRIPTORS_DB}/{descriptor_filename}', 'rb') as f:
                descriptors[img] = pickle.load(f)

    return descriptors


def score_function(parameters, descriptors, descriptors_grouped_by_name, decision, times, name,
                   generate_confusion_matrix=False):
    voting_size_terminations, voting_size_bifurcations = 0, 0
    if len(parameters) == 3:
        terminations_threshold, bifurcations_threshold, db_size = parameters
    else:
        terminations_threshold, bifurcations_threshold, db_size, voting_size_terminations, voting_size_bifurcations = parameters
    db_size = int(db_size)

    y_true = []
    y_pred = []
    images = list(descriptors.keys())
    for i in range(len(images)):
        for j in range(i + 1, len(images)):
            desc_terminations2, desc_bifurcations2 = descriptors[images[j]]

            params1, params2 = get_params_from_filename(images[i]), get_params_from_filename(images[j])

            if params1[1:-1] == params2[1:-1]:
                y_true.append(1)
            else:
                y_true.append(-1)

            images_names_matcher = [x for x in descriptors_grouped_by_name[params1[1:-1]] if x != images[j]]
            random.shuffle(images_names_matcher)

            this_descriptors = [descriptors[x] for x in images_names_matcher[:db_size]]
            scores_terminations, scores_bifurcations = get_matching_score(this_descriptors,
                                                                          (desc_terminations2, desc_bifurcations2))

            args = [scores_terminations, scores_bifurcations]
            if decision == 'voting':
                args += [terminations_threshold, bifurcations_threshold]

            final_score_terminations, final_score_bifurcations = DECISIONS.get(decision)(*args)

            if decision == 'voting':
                prediction = int(
                    final_score_terminations <= voting_size_terminations and
                    final_score_bifurcations <= voting_size_bifurcations
                )
            else:
                prediction = int(
                    final_score_terminations <= terminations_threshold and
                    final_score_bifurcations <= bifurcations_threshold
                )
            if prediction == 0:
                prediction = -1
            y_pred.append(prediction)

    mcc = matthews_corrcoef(y_true, y_pred)
    acc = accuracy_score(y_true, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    if generate_confusion_matrix:
        params = [int(i) for i in parameters[2:]]
        start_time = 0
        if not times.empty():
            start_time = times.get()
        delta = time.time() - start_time

        data = {
            'decision': decision,
            'terminations_threshold': terminations_threshold,
            'bifurcations_threshold': bifurcations_threshold,
            'params': params,
            'tn': tn,
            'fp': fp,
            'fn': fn,
            'tp': tp,
            'mcc': mcc,
            'acc': acc,
            'score': (tp / (tp + fp)) * math.sqrt(tp / (tp + fn)),
            'delta': delta

        }
        save_scores_per_iteration(decision, name, data)

    return (1 - (tp / (tp + fp)) * math.sqrt(tp / (tp + fn))) if tp != 0 else 1


def cb(descriptors, descriptors_grouped_by_name, decision, times, name, x, convergence):
    print(f"{x=}")
    score_function(x, descriptors, descriptors_grouped_by_name, decision, times, name, True)


def main(args):
    decision, name, data_path = args.decision, args.name, args.input

    Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)
    images = os.listdir(data_path)[:10]
    descriptors_saved = os.listdir(DESCRIPTORS_DB)

    n_process = mp.cpu_count()
    pool = mp.Pool(processes=n_process)

    results = [pool.apply_async(generate_images_descriptors, args=(sub_images, data_path, descriptors_saved,))
               for sub_images in np.array_split(images, n_process)]
    results = [p.get() for p in results]
    descriptors = {k: v for x in results for k, v in x.items()}
    descriptors_grouped_by_name = {}

    for img in descriptors:
        params = get_params_from_filename(img)[1:-1]
        if params not in descriptors_grouped_by_name:
            descriptors_grouped_by_name[params] = []

        descriptors_grouped_by_name[params].append(img)

    bounds = [(0, 100)] * 2 + [(1, voting_size + 1)]

    if decision == 'voting':
        bounds += [(1, voting_size + 1)] * 2

    manager = mp.Manager()
    times = manager.Queue(1)

    cb_partial = functools.partial(cb, descriptors, descriptors_grouped_by_name, decision, times, name)
    optimizer = differential_evolution(func=score_function, bounds=bounds,
                                       args=(descriptors, descriptors_grouped_by_name, decision, times, name),
                                       workers=n_process,
                                       disp=True, maxiter=100, tol=0.001, callback=cb_partial)

    with open(f'{LOGS_DIR}/thresholds_{name}_{START}_{decision}.json', 'w') as fp:
        json.dump({
            'x': optimizer.x.tolist(),
            'fun': optimizer.fun.tolist()
        }, fp)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Optimization algorithm to find the needed parameters in fingerprint authentication')
    parser.add_argument('--decision', '-d', type=str, default='min', help="Decision process",
                        choices=list(DECISIONS.keys()))
    parser.add_argument('--name', '-n', type=str, required=True, help='Execution name')
    parser.add_argument('--input', '-i', type=str, default='fingerprints_database/fingerprints_upscaled',
                        help="Fingeprint' images path")
    main(parser.parse_args())
