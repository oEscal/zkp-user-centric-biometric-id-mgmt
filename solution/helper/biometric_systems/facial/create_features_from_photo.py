import sys
import os

import cv2.cv2
import face_recognition

from facial_recognition import Face_biometry, get_features_from_face
import pickle


def dumb(*args, **kwargs):
	pass


def main(username: str, take: int):
	final_dir = f"gathered_photos/{username}/{take}"

	features = []

	photos_names = os.listdir(final_dir)
	for photos_name in photos_names:
		img = cv2.cv2.imread(f"{final_dir}/{photos_name}", 0)

		faces = face_recognition.face_locations(img)
		if not faces:
			faces = face_recognition.face_locations(img, model='cnn')
		features.append(get_features_from_face(cv2.cvtColor(img, cv2.COLOR_BGR2RGB),
		                                       [faces[0]]))

	with open(f"{final_dir}/features", 'wb') as file:
		file.write(pickle.dumps(features))


if __name__ == '__main__':
	username = sys.argv[1]
	take = int(sys.argv[2])

	main(username=username, take=take)
