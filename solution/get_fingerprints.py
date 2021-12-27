from pathlib import Path
from PIL import Image
import adafruit_fingerprint
import serial
import time

POSITIONS = 3
SCANS_PER_IMAGE = 10
# SCANS_PER_IMAGE_LIST = [2, 3, 5, 10, 15]
DATA_FOLDER = 'fingerprints'
Path(DATA_FOLDER).mkdir(parents=True, exist_ok=True)


def enroll_finger(finger, finger_path_id, scans_per_image):
    """Take a 2 finger images and template it, then store in 'location'"""
    for finger_img in range(1, POSITIONS + 1):
        if finger_img == 1:
            print(f"Place finger on sensor (Position {finger_img})...", end="", flush=True)
        else:
            print(f"Place same finger again (Position {finger_img})...", end="", flush=True)

        scan_counter = 1
        while True:
            if scan_counter > scans_per_image:
                break
            i = finger.get_image()
            if i == adafruit_fingerprint.OK:
                print(f"Scan {scan_counter}")
                scan_counter += 1
            if i == adafruit_fingerprint.NOFINGER:
                print(".", end="", flush=True)

        img = Image.new("L", (256, 288), "white")
        pixel_data = img.load()
        mask = 0b00001111
        result = finger.get_fpdata("image")
        x = 0
        y = 0
        for i in range(len(result)):
            pixel_data[x, y] = (int(result[i]) >> 4) * 17
            x += 1
            pixel_data[x, y] = (int(result[i]) & mask) * 17
            if x == 255:
                x = 0
                y += 1
            else:
                x += 1

        finger_path = f'{DATA_FOLDER}/{finger_img}_{finger_path_id}.png'
        img.save(finger_path)


def finger_name():
    menu = """
    1) Thumb
    2) Index finger
    3) Middle finger
    4) Ring finger
    5) Little finger
    >
    """
    while True:
        try:
            finger_option = input(menu)
            value = int(finger_option)
            if value in range(1, 6):
                break
        except:
            print("Invalid option")

    return value


def hand_side():
    menu = """
    l) left
    r) right
    >
    """
    while True:
        side_option = input(menu).lower()
        if side_option in ['l', 'r']:
            break

    return side_option


def main():
    uart = serial.Serial("/dev/ttyUSB0", baudrate=57600, timeout=1)
    finger = adafruit_fingerprint.Adafruit_Fingerprint(uart)

    while True:
        print("----------------")
        if finger.read_templates() != adafruit_fingerprint.OK:
            raise RuntimeError("Failed to read templates")

        print("Save fingerprint")
        print("e) enroll print")
        print("q) quit")
        print("----------------")
        option = input("> ")

        if option == "e":
            name = input("Name: \n> ")
            side = hand_side()
            finger_id = finger_name()
            current_time = int(time.time())

            finger_path_id = f'{name}_{side}_{finger_id}_{current_time}'
            enroll_finger(finger, finger_path_id, SCANS_PER_IMAGE)

        elif option == "q":
            print("Quitting")
            break


if __name__ == '__main__':
    main()
