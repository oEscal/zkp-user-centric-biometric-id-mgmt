import base64
import time
from multiprocessing import Process, Manager, Queue

import cv2
import face_recognition
import numpy as np
from threading import Thread


def get_features_from_face(frame: np.ndarray, face_locations: list[list]) -> list[float]:
    return face_recognition.face_encodings(frame, known_face_locations=face_locations, model='large')[0].tolist()


class Face_biometry:
    def __init__(self, ws, min_distance=0.35, path_save=''):
        self.ws = ws
        self.min_distance = min_distance
        self.path_save = path_save

        self.__take_shot = False
        self.__stop_camera = False

        self.video_capture = cv2.VideoCapture(0)
        _, self.frame = self.video_capture.read()

        self.frames_queue = Queue(1)

    def __camera(self):
        init = time.time()
        while not self.__stop_camera:
            # Capture frame-by-frame
            _, self.frame = self.video_capture.read()

            # in the beginning, give a sec to warmup the camera
            if self.frames_queue.empty() and time.time() - init > 1:
                self.frames_queue.put(self.frame)

        self.video_capture.release()

    def __interface(self):
        while not self.__stop_camera:
            face_b64 = base64.b64encode(cv2.imencode('.jpg', self.frame)[1]).decode()
            self.ws(face_b64, operation="fingerprint_image")

    def __get_face_features(self, final_face_features, number_faces, frames_queue):
        # wait a sec to allow the camera to warmup
        n = 0
        while True:
            frame = frames_queue.get()
            if frame is not None:
                faces = face_recognition.face_locations(frame)
                if len(faces) > 0:
                    face = faces[0]
                    current_features = get_features_from_face(frame=cv2.cvtColor(frame, cv2.COLOR_BGR2RGB),
                                                              face_locations=[face])

                    # verify the captured face with all the faces captured until now
                    add_face = True
                    for comp_face in final_face_features:
                        if np.linalg.norm(np.asarray(current_features) - np.asarray(comp_face)) < self.min_distance:
                            add_face = False
                            break
                    if add_face:
                        # cv2.imwrite(f'{self.path_save}frame{n}.jpg', frame)
                        face_b64 = base64.b64encode(cv2.imencode('.jpg', frame)[1]).decode()
                        self.ws(face_b64, operation="new_face")

                        n += 1
                        final_face_features.append(current_features)
                        print(f"Face {len(final_face_features)}/{number_faces} captured")
                        self.ws(f"Face {len(final_face_features)}/{number_faces} captured\n")

                if len(final_face_features) >= number_faces:
                    print("Finished")
                    self.ws(operation="finish")
                    break

    def get_facial_features(self, number_faces) -> list[list[float]]:
        manager = Manager()
        final_face_features = manager.list()
        threads = [Process(target=self.__get_face_features, args=(final_face_features, number_faces, self.frames_queue)),
                   Thread(target=self.__camera),
                   Thread(target=self.__interface)]

        # start threads
        for t in threads:
            t.start()
            print("Thread started")

        # self.__interface()

        print("All threads started")

        # self.__take_shoot()

        # join threads
        for t in threads:
            # TODO - MUDAR ISTO
            t.join()
            self.__stop_camera = True
            print("Thread joined")

        return list(final_face_features)
