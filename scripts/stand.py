#!/usr/bin/python3
# -*- coding: utf-8 -*-

import imageio
import argparse
import os
import numpy as np
import sys
import socket
import logging
import datetime

def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data

def ClientInterface(args):

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP socket
    client_socket.connect((args.host, int(args.port)))
    logging.info('The client TCP socket was opened')

    output_file = args.input_file + '.enc'

    res = os.system('./build/enc -e encrypt -c chacha20 -i ' + args.input_file + ' -o ' + output_file)

    out = open(output_file, 'rb')
    data = out.read()
    out.close()

    logging.info('The client sent a message to the server %s:%d', args.host, int(args.port))

    client_socket.send(data)

    client_socket.close()
    logging.info('The client TCP socket was closed')


def ServerInterface(args):

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((args.host, int(args.port)))
    server_socket.listen(1)
    logging.info('The server is ready to receive')

    while 1:
        connection_socket, client_address = server_socket.accept()
        logging.info('The TCP connection to the client %s:%d has been set up',
                     client_address[0], client_address[1])

        data = recvall(connection_socket)

        current_time = datetime.datetime.now()
        output_file = f'{current_time.year}_{current_time.month}_{current_time.day}_{current_time.hour}_{current_time.minute}_{current_time.second}'

        out = open(output_file, 'wb')
        out.write(data)
        out.close()

        res = os.system('./build/enc -e decrypt -c chacha20 -i ' + output_file + ' -o ' + output_file)

        connection_socket.close()
        logging.info('The TCP connection socket was closed')

def main():

    parser = argparse.ArgumentParser(description='Stand')

    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Echo system command or not')

    parser.add_argument('host', help='Host address')
    parser.add_argument('port', help='Port')

    subparsers = parser.add_subparsers(help='client/server', dest='target')

    client_parser = subparsers.add_parser('client', help='client')
    server_parser = subparsers.add_parser('server', help='server')

    client_parser.add_argument('-i', dest='input_file', action='store',
                               help='input file', required=True)

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')

    if (args.target == 'client'):
        ClientInterface(args)
    else:
        ServerInterface(args)



if __name__ == "__main__":
    main()
