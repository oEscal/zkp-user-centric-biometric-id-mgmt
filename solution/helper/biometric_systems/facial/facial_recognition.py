import cv2
import face_recognition
import numpy as np
import threading


def get_features_from_face(frame: np.ndarray, face_locations: list[list]) -> list[float]:
    return face_recognition.face_encodings(frame, known_face_locations=face_locations, model='large')[0].tolist()


class Face_biometry:
    def __init__(self, min_distance=0.4):
        self.min_distance = min_distance

        self.frame = None
        self.__stop_camera = False

    def __camera(self):
        video_capture = cv2.VideoCapture(0)
        # take_shot = False

        while True:
            # Capture frame-by-frame
            _, self.frame = video_capture.read()

            # if cv2.waitKey(1) & 0xFF == ord('s'):
            # 	take_shot = True

            cv2.waitKey(1)

            if self.__stop_camera:
                video_capture.release()
                cv2.destroyAllWindows()
                return

            cv2.imshow('Video', self.frame)

    def __get_face_features(self, final_face_features, number_faces):
        n = 0
        while True:
            if self.frame is not None:
                faces = face_recognition.face_locations(self.frame)
                if len(faces) > 0:
                    face = faces[0]
                    current_features = get_features_from_face(frame=cv2.cvtColor(self.frame, cv2.COLOR_BGR2RGB),
                                                              face_locations=[face])

                    # verify the captured face with all the faces captured until now
                    add_face = True
                    for comp_face in final_face_features:
                        if np.linalg.norm(np.asarray(current_features) - np.asarray(comp_face)) < self.min_distance:
                            add_face = False
                            break
                    if add_face:
                        cv2.imwrite(f'frame{n}.jpg', self.frame)
                        n += 1
                        print("Face Added")
                        final_face_features.append(current_features)

                if len(final_face_features) >= number_faces:
                    self.__stop_camera = True
                    return final_face_features

    def get_facial_features(self, number_faces) -> list[list[float]]:
        final_face_features = []
        threads = [threading.Thread(target=self.__camera),
                   threading.Thread(target=self.__get_face_features, args=(final_face_features, number_faces))]

        # start threads
        for t in threads:
            t.start()
            print("Thread started")

        print("All threads started")

        # self.__take_shoot()

        # join threads
        for t in threads:
            t.join()
            print("Thread joined")

        return final_face_features
