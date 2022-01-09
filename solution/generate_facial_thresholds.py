import math
import pickle
import time

from scipy.optimize import differential_evolution
from sklearn.metrics import matthews_corrcoef, confusion_matrix, accuracy_score

from idp.biometric_systems.facial.face import Faces
import multiprocessing as mp
import numpy as np
import os
import functools

DATA_PATH = 'helper/biometric_systems/facial/gathered_photos'
LOGS_DIR = "logs"
START = time.time()

DECISIONS = ['mean', 'max', 'min', 'voting']


def get_params_from_filename(file_name):
    image_index, name, side, finger_id, acquisition_time = file_name.split('_')
    return int(image_index), name, side, int(finger_id), int(acquisition_time.split('.')[0])


def generate_images_descriptors(users):
    all_features = {}
    for user in users:
        all_features[user] = []
        all_takes = os.listdir(f"{DATA_PATH}/{user}")

        for take in all_takes:
            with open(f"{DATA_PATH}/{user}/{take}/features", 'rb') as file:
                features = pickle.loads(file.read())
            all_features[user] += features

    return all_features


def score_function(parameters, all_features, generate_confusion_matrix=False):
    tolerance = parameters[0]
    y_true = []
    y_pred = []
    for user_true in all_features:
        for index_true in range(len(all_features[user_true])):
            faces = Faces(username=user_true, save_faces_funct=lambda x, y: None,
                          get_faces_funct=lambda x: pickle.dumps([all_features[x][index_true]]))
            for user_to_verify in all_features:
                for index_to_verify in range(index_true+1 if user_true == user_to_verify else 0, len(all_features[user_to_verify])):
                    scores = faces.verify_user_all_distances(np.array(all_features[user_to_verify][index_to_verify]))
                    prediction = int(score <= tolerance)
                    y_pred.append(1 if user_true == user_to_verify else -1)
                    y_true.append(prediction if prediction == 1 else -1)

    mcc = matthews_corrcoef(y_true, y_pred)
    acc = accuracy_score(y_true, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    if generate_confusion_matrix:
        with open(f'{LOGS_DIR}/confusion_matrix_{START}.log', 'a') as f:
            f.write(f'{tn=} {fp=} {fn=} {tp=} {mcc=} {acc=} {(tp / (tp + fp))*math.sqrt(tp/(tp+fn))=}\n')

    return (1 - (tp / (tp + fp))*math.sqrt(tp/(tp+fn))) if tp != 0 else 1 # 1 - mcc * (tp / (tp + fp))


def score_function_2(parameters, all_features, generate_confusion_matrix=False):
    tolerance = parameters[0]
    y_true = []
    y_pred = []
    for user_true in all_features:
        for index_true in range(len(all_features[user_true]) - 1):
            faces = Faces(username=user_true, save_faces_funct=lambda x, y: None,
                          get_faces_funct=lambda x: pickle.dumps([all_features[x][index_true], all_features[x][index_true+1]]))
            for user_to_verify in all_features:
                for index_to_verify in range(index_true+1+1 if user_true == user_to_verify else 0, len(all_features[user_to_verify])):
                    score = faces.verify_user(np.array(all_features[user_to_verify][index_to_verify]))
                    prediction = int(score <= tolerance)
                    y_pred.append(1 if user_true == user_to_verify else -1)
                    y_true.append(prediction if prediction == 1 else -1)

    mcc = matthews_corrcoef(y_true, y_pred)
    acc = accuracy_score(y_true, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    if generate_confusion_matrix:
        with open(f'{LOGS_DIR}/confusion_matrix_{START}.log', 'a') as f:
            f.write(f'{tn=} {fp=} {fn=} {tp=} {mcc=} {acc=} {(tp / (tp + fp))*math.sqrt(tp/(tp+fn))=}\n')

    return (1 - (tp / (tp + fp))*math.sqrt(tp/(tp+fn))) if tp != 0 else 1   # 1 - mcc * (tp / (tp + fp))


def cb(all_features, x, convergence):
    tolerance = x
    print(f"{tolerance=}")
    score_function(x, all_features, True)


def main():
    users = [f for f in os.listdir(DATA_PATH) if os.path.isdir(os.path.join(DATA_PATH, f))]
    print(f"Number of users: {len(users)}")

    n_process = min(mp.cpu_count(), len(users))
    pool = mp.Pool(processes=n_process)

    results = [pool.apply(generate_images_descriptors, args=(sub_images,)) for sub_images in
               np.array_split(users, n_process)]

    all_features = {k: v for x in results for k, v in x.items()}

    bounds = [(0, 1), tuple(range(len(DECISIONS)))]

    cb_partial = functools.partial(cb, all_features)
    optimizer = differential_evolution(func=score_function_2, bounds=bounds,
                                       args=(all_features, ), workers=mp.cpu_count()-4,
                                       disp=True, maxiter=250, tol=0, callback=cb_partial)

    print(f"Results: {optimizer.x}")
    print(f"Score: {optimizer.fun}")


if __name__ == '__main__':
    main()
