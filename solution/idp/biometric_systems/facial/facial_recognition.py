from typing import Callable

import numpy as np

from idp.biometric_systems.facial.face import Faces


class Face_biometry:
	def __init__(self, username: str, save_faces_funct: Callable[[str, bytes], bool],
				 get_faces_funct: Callable[[str], tuple[bytes]]):
		self.username = username

		self.faces = Faces(username=username, save_faces_funct=save_faces_funct, get_faces_funct=get_faces_funct)

	def register_new_user(self, faces_features) -> bool:
		for features in faces_features:
			self.faces.add(new_face_features=features)
		if self.faces.save_faces():
			return True
		return False

	def verify_user(self, face_features: list[float], tolerance=0.4) -> bool:
		all_verifications = self.faces.verify_user(np.array(face_features))
		print(f"Distance: {all_verifications}")

		return all_verifications <= tolerance
