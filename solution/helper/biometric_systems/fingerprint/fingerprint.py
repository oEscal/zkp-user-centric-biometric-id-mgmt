import adafruit_fingerprint
import serial


class Fingerprint:
    def __init__(self, n_img=3):
        self.uart = serial.Serial("/dev/ttyUSB0", baudrate=57600, timeout=1)
        self.finger = adafruit_fingerprint.Adafruit_Fingerprint(self.uart)
        self.n_img = n_img

    def enroll_finger(self):
        for finger_img in range(1, self.n_img + 1):
            pass

    """
    def get_fingerprint(self):
        print("Waiting for image...")
        while self.finger.get_image() != adafruit_fingerprint.OK:
            pass
    """
