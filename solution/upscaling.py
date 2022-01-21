from pathlib import Path
import cv2
import os
import time
import json
import multiprocessing as mp
import numpy as np


def upscaler(images, model, original_folder_name, upscaled_folder_name, times):
    sr = cv2.dnn_superres.DnnSuperResImpl_create()
    sr.readModel(model)
    lower_model_name = model.split('_')[0].lower()
    sr.setModel(lower_model_name, 2)

    Path(f'{upscaled_folder_name}_{lower_model_name}').mkdir(parents=True, exist_ok=True)

    for img_path in images:
        print(img_path)
        full_path = f'{original_folder_name}/{img_path}'

        img = cv2.imread(full_path)
        start_time = time.time()
        up_img = sr.upsample(img)
        times[model][img_path] = time.time() - start_time
        cv2.imwrite(f'{upscaled_folder_name}_{lower_model_name}/{img_path}', up_img)


def main():
    models_names = [i for i in os.listdir() if i.endswith('.pb')][1:]
    original_folder_name = 'fingerprints_database/fingerprints_class'
    original_images = os.listdir(original_folder_name)[:8]
    n_process = mp.cpu_count()
    splitted_images = np.array_split(original_images, n_process)

    pool = mp.Pool(processes=n_process)
    results = []

    times = {}
    for model in models_names:
        times[model] = mp.Manager().dict()
        for sub_images in splitted_images:
            results.append(pool.apply_async(upscaler, args=(
                sub_images, model, original_folder_name, 'fingerprints_database/fingerprints_class_upscaled', times)))

    results = [p.get() for p in results]
    pool.close()
    pool.join()
    
    Path(f'logs/upscaling_time').mkdir(parents=True, exist_ok=True)

    full_data = {}
    for model in times:
        truncated_model_name = model.replace('.pb', '')
        data = dict(times[model])
        full_data[truncated_model_name] = {
            'data': data,
            'total': sum(data.values())
        }

    with open(f'logs/upscaling_time/elapsed_time.json', 'w') as f:
        json.dump(full_data, f)


if __name__ == '__main__':
    main()
