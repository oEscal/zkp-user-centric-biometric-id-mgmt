from pathlib import Path
from sample import overall_image_quality, enhance_image
import cv2
import os
import multiprocessing as mp
import numpy as np

UPSCALED_FOLDER_NAME = 'fingerprints_upscaled'
FOLDER_NAME = 'fingerprints'
QUALITY_THRESHOLD = 0.75


def upscaler(images):
    sr = cv2.dnn_superres.DnnSuperResImpl_create()
    sr.readModel('FSRCNN_x2.pb')
    sr.setModel("fsrcnn", 2)

    for img_path in images:
        full_path = f'{FOLDER_NAME}/{img_path}'

        img = cv2.imread(full_path)
        quality_score = overall_image_quality(enhance_image(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)))

        if quality_score > QUALITY_THRESHOLD:
            continue
        print(quality_score)
        print(img_path)
        up_img = sr.upsample(img)
        cv2.imwrite(f'{UPSCALED_FOLDER_NAME}/{img_path}', up_img)


def main():
    Path(UPSCALED_FOLDER_NAME).mkdir(parents=True, exist_ok=True)
    n_process = mp.cpu_count()

    images = os.listdir(FOLDER_NAME)
    images_upscaled = os.listdir(UPSCALED_FOLDER_NAME)
    images = list(set(images) - set(images_upscaled))

    pool = mp.Pool(processes=n_process)
    results = [pool.apply(upscaler, args=(sub_images,)) for sub_images in
               np.array_split(images, n_process)]

    pool.close()
    pool.join()


if __name__ == '__main__':
    main()
