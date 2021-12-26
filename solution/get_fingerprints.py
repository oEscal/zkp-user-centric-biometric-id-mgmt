from pathlib import Path
import adafruit_fingerprint
import serial

IMAGES = 3
SCANS_PER_IMAGE = 5
DATA_FOLDER = 'fingerprints/'
Path(DATA_FOLDER).mkdir(parents=True, exist_ok=True)


# pylint: disable=too-many-statements
def enroll_finger(finger, location):
    """Take a 2 finger images and template it, then store in 'location'"""
    for finger_img in range(1, IMAGES + 1):
        if finger_img == 1:
            print("Place finger on sensor...", end="", flush=True)
        else:
            print("Place same finger again...", end="", flush=True)

        scan_counter = 0
        while True:
            if scan_counter == 5:
                break
            i = finger.get_image()
            if i == adafruit_fingerprint.OK:
                print("Image taken")
                scan_counter += 1
            if i == adafruit_fingerprint.NOFINGER:
                print(".", end="", flush=True)
            elif i == adafruit_fingerprint.IMAGEFAIL:
                print("Imaging error")
                # return False
            else:
                print("Other error")
                # return False

        from PIL import Image
        img = Image.new("L", (256, 288), "white")
        pixeldata = img.load()
        mask = 0b00001111
        result = finger.get_fpdata("image")
        x = 0
        # pylint: disable=invalid-name
        y = 0
        # pylint: disable=consider-using-enumerate
        for i in range(len(result)):
            pixeldata[x, y] = (int(result[i]) >> 4) * 17
            x += 1
            pixeldata[x, y] = (int(result[i]) & mask) * 17
            if x == 255:
                x = 0
                y += 1
            else:
                x += 1

        # import numpy as np
        # pixeldata = np.asarray(pixeldata, dtype="uint8")
        img.save(f'enroll_{finger_img}.png')


def get_num():
    """Use input() to get a valid number from 1 to 127. Retry till success!"""
    i = 0
    while (i > 127) or (i < 1):
        try:
            i = int(input("Enter ID # from 1-127: "))
        except ValueError:
            pass
    return i


def main():
    uart = serial.Serial("/dev/ttyUSB0", baudrate=57600, timeout=1)
    finger = adafruit_fingerprint.Adafruit_Fingerprint(uart)

    while True:
        print("----------------")
        if finger.read_templates() != adafruit_fingerprint.OK:
            raise RuntimeError("Failed to read templates")
        print("Fingerprint templates:", finger.templates)
        print("e) enroll print")
        print("f) find print")
        print("d) delete print")
        print("----------------")
        c = input("> ")

        if c == "e":
            enroll_finger(get_num())
        if c == "f":
            if get_fingerprint():
                print("Detected #", finger.finger_id, "with confidence", finger.confidence)
            else:
                print("Finger not found")
        if c == "d":
            if finger.delete_model(get_num()) == adafruit_fingerprint.OK:
                print("Deleted!")
            else:
                print("Failed to delete")


if __name__ == '__main__':
    main()
