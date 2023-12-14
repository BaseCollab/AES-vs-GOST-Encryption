#!/usr/bin/python3
# -*- coding: utf-8 -*-

import imageio
import argparse
import os
import numpy as np

def Encrypt(args):

    video = imageio.get_reader(args.input_file)

    temp_file = args.input_file + '.raw'
    enc_file = temp_file + '.enc'

    out_video = imageio.get_writer(args.output_file, fps=30)

    for frame in video.iter_data():

        with open(temp_file, 'wb') as output:
            output.write(frame)

        os.system('./build/enc -e decrypt -c chacha20 -i ' + temp_file + ' -o ' + enc_file)

        encrypted_file = open(enc_file, 'rb')
        raw_encrypted_data = bytearray(list(encrypted_file.read()));

        encrypted_file.close()

        raw_encrypted_data = np.asarray(raw_encrypted_data).reshape(720, 1280, 3)

        out_video.append_data(raw_encrypted_data)

    out_video.close()

def Decrypt(args):

    video = imageio.get_reader(args.input_file)

    temp_file = args.input_file + '.raw'
    enc_file = temp_file + '.enc'

    out_video = imageio.get_writer(args.output_file, fps=30)

    for frame in video.iter_data():

        with open(temp_file, 'wb') as output:
            output.write(frame)

        os.system('./build/enc -e encrypt -c chacha20 -i ' + temp_file + ' -o ' + enc_file)

        encrypted_file = open(enc_file, 'rb')
        raw_encrypted_data = bytearray(list(encrypted_file.read()));

        encrypted_file.close()

        raw_encrypted_data = np.asarray(raw_encrypted_data).reshape(720, 1280, 3)

        out_video.append_data(raw_encrypted_data)

    out_video.close()

def main():

    parser = argparse.ArgumentParser(description='Generate raw data video')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Echo system command or not')
    parser.add_argument('-i', dest='input_file', action='store',
                        help='input video file', required=True)
    parser.add_argument('-o', dest='output_file', action='store',
                        help='output raw data', required=True)
    parser.add_argument(dest='mode', choices=['encrypt', 'decrypt'],
                        help='encryption mode')

    args = parser.parse_args()

    if args.mode == 'encrypt':
        Encrypt(args)
    else:
        Decrypt(args)


if __name__ == "__main__":
    main()
