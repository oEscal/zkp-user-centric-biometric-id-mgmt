import cv2
import numpy as np

from idp.biometric_systems.facial.face import Faces

faceCascade = cv2.CascadeClassifier(f'{cv2.data.haarcascades}haarcascade_frontalface_alt2.xml')

DEFAULT_NUMBER_FACES = 5


class Face_biometry:
	def __init__(self, username: str):
		self.username = username

		self.faces = Faces(username=username)

	def verify_user(self, face_features: list[float], tolerance=0.4) -> bool:
		all_verifications = self.faces.verify_user(np.array(face_features))
		print(all_verifications)

		return all_verifications <= tolerance
