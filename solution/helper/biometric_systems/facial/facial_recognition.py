import base64
import json

import cv2
import face_recognition
import numpy as np

from helper.biometric_systems.facial.face import get_features_from_face, Faces

faceCascade = cv2.CascadeClassifier(f'{cv2.data.haarcascades}haarcascade_frontalface_alt2.xml')

DEFAULT_NUMBER_FACES = 5


class Face_biometry:
	def __init__(self):
		self.faces = Faces(username='')

	@staticmethod
	def __take_shoot() -> (np.ndarray, list[list]):
		video_capture = cv2.VideoCapture(0)
		take_shot = False

		while True:
			# Capture frame-by-frame
			ret, frame = video_capture.read()

			"""
			gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

			faces = faceCascade.detectMultiScale(
				gray,
				scaleFactor=1.5,
				minNeighbors=5,
				# minSize=(60, 60),
				# flags=cv2.CASCADE_SCALE_IMAGE
			)
			"""

			if cv2.waitKey(1) & 0xFF == ord('s'):
				take_shot = True

			# Draw a rectangle around the faces
			if take_shot:
				for face in face_recognition.face_locations(frame):
					video_capture.release()
					cv2.destroyAllWindows()
					return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB), [face]

			# for (x, y, w, h) in faces:
			#     cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)

			# Display the resulting frame
			cv2.imshow('Video', frame)

			"""
			if cv2.waitKey(1) & 0xFF == ord('s'):
				ret, frame = video_capture.read()

				video_capture.release()
				cv2.destroyAllWindows()

				return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
			"""

	def register_new_user(self):
		for i in range(DEFAULT_NUMBER_FACES):
			frame, face_locations = self.__take_shoot()
			face_features = get_features_from_face(frame=frame, face_locations=face_locations)

			self.faces.add(new_face_features=face_features)
		self.faces.save_faces()
		print("All facial features saved with success")

	def get_facial_features(self) -> list[float]:
		frame, face_locations = self.__take_shoot()
		return get_features_from_face(frame=frame, face_locations=face_locations)

	def verify_user(self, face_features: list[float]):
		all_verifications = self.faces.verify_user(face_features)

		true_ctr = 0
		false_ctr = 0
		for verification in all_verifications:
			if verification:
				true_ctr += 1
			else:
				false_ctr += 1

		print(f"True percentage: {true_ctr / len(all_verifications) * 100}%")
		print(f"False percentage: {false_ctr / len(all_verifications) * 100}%")
		return true_ctr / len(all_verifications)
