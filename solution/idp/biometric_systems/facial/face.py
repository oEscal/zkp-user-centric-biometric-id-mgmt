from typing import Callable

import face_recognition
import numpy as np
import pickle


MIN_VOTERS = 2
TOLERANCE = 0.53


def get_features_from_face(frame: np.ndarray, face_locations: list[list]) -> list[float]:
    return face_recognition.face_encodings(frame, known_face_locations=face_locations, model='large')[0].tolist()


class Faces:
    def __init__(self, username: str, save_faces_funct: Callable[[str, bytes], bool],
                 get_faces_funct: Callable[[str], tuple[bytes]]):
        self.username = username

        self.pre_defined_faces: list[list[float]] = []

        self.save_faces_db = save_faces_funct
        self.get_faces_db = get_faces_funct

        self.__load_faces()

    def add(self, new_face_features: list[float]):
        self.pre_defined_faces.append(new_face_features)

    def verify_user(self, face_cmp: np.ndarray) -> bool:
        scores: np.ndarray = face_recognition.face_distance(self.pre_defined_faces, face_cmp)
        votes_favor = 0
        for score in scores:
            if score <= TOLERANCE:
                votes_favor += 1
        return votes_favor >= MIN_VOTERS

    def verify_user_all_distances(self, face_cmp: np.ndarray) -> np.ndarray:
        distances: np.ndarray = face_recognition.face_distance(self.pre_defined_faces, face_cmp)
        return distances

    def save_faces(self) -> bool:
        print(self.username)
        return self.save_faces_db(self.username, pickle.dumps(self.pre_defined_faces))

    def __load_faces(self):
        faces = self.get_faces_db(self.username)
        if faces:
            self.pre_defined_faces = pickle.loads(faces)
