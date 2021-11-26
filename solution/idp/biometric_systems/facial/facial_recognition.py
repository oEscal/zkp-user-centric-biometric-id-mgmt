from typing import Callable

import cv2
import numpy as np

from idp.biometric_systems.facial.face import Faces, get_features_from_face

faceCascade = cv2.CascadeClassifier(f'{cv2.data.haarcascades}haarcascade_frontalface_alt2.xml')

DEFAULT_NUMBER_FACES = 5


class Face_biometry:
	def __init__(self, username: str, save_faces_funct: Callable[[str, bytes], bool],
				 get_faces_funct: Callable[[str], tuple[bytes]]):
		self.username = username

		self.faces = Faces(username=username, save_faces_funct=save_faces_funct, get_faces_funct=get_faces_funct)

	def register_new_user(self):
		for i in range(DEFAULT_NUMBER_FACES):
			frame, face_locations = ()		# self.__take_shoot()
			face_features = get_features_from_face(frame=frame, face_locations=face_locations)

			self.faces.add(new_face_features=face_features)
		self.faces.save_faces()
		print("All facial features saved with success")

	def verify_user(self, face_features: list[float], tolerance=0.4) -> bool:
		all_verifications = self.faces.verify_user(np.array(face_features))
		print(all_verifications)

		return all_verifications <= tolerance
