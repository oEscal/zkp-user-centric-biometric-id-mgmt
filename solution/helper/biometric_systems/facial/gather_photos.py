import sys
import os

from facial_recognition import Face_biometry
import pickle


def dumb(*args, **kwargs):
	pass


def main(username):
	current_dir = f"gathered_photos/{username}"
	dir_inside = 0

	try:
		os.mkdir(current_dir)
	except:
		dir_list = [int(i) for i in os.listdir(current_dir)]
		dir_inside = max(dir_list) + 1 if dir_list else dir_inside
		print("QUERO DORMIR RAFA")

	final_dir = f"{current_dir}/{dir_inside}/"

	os.mkdir(final_dir)

	face_biometry = Face_biometry(ws=dumb, path_save=final_dir)
	features = face_biometry.get_facial_features(number_faces=14)
	with open(f"{final_dir}/features", 'wb') as file:
		file.write(pickle.dumps(features))


if __name__ == '__main__':
	username = sys.argv[1]

	main(username=username)
