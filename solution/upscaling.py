from pathlib import Path
import cv2
import os
import multiprocessing as mp
import numpy as np

UPSCALED_FOLDER_NAME = 'fingerprints_upscaled'
FOLDER_NAME = 'fingerprints'


def upscaler(images):
    sr = cv2.dnn_superres.DnnSuperResImpl_create()
    sr.readModel('EDSR_x2.pb')
    sr.setModel("edsr", 2)

    for img_path in images:
        print(img_path)
        full_path = f'{FOLDER_NAME}/{img_path}'

        img = cv2.imread(full_path)
        up_img = sr.upsample(img)
        cv2.imwrite(f'{UPSCALED_FOLDER_NAME}/{img_path}', up_img)


def main():
    Path(UPSCALED_FOLDER_NAME).mkdir(parents=True, exist_ok=True)
    n_process = mp.cpu_count()

    images = os.listdir(FOLDER_NAME)
    images_upscaled = os.listdir(UPSCALED_FOLDER_NAME)
    images = list(set(images) - set(images_upscaled))

    pool = mp.Pool(processes=n_process)
    results = [pool.apply_async(upscaler, args=(sub_images,)) for sub_images in
               np.array_split(images, n_process)]
    results = [p.get() for p in results]


if __name__ == '__main__':
    main()
