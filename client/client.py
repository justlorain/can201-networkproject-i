import sys
from socket import *
import json
import os
from os.path import join, getsize

import argparse
from threading import Thread
import struct
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import base64
import uuid
import math
import shutil
import hashlib

# import tqdm

# type
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
# operation
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
# direction
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'
# other
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'

logger = logging.getLogger('')


def parse_cmd_args():
    parser = argparse.ArgumentParser()
    # server ip
    parser.add_argument("--server_ip", default="127.0.0.1", action="store", required=False, dest="server_ip",
                        help="The IP address bind to the server. Default bind all IP.")
    # server port
    parser.add_argument("--port", default=8080, action="store", required=False, type=int, dest="port",
                        help="The port that server listen on. Default is 8080")
    # student id
    parser.add_argument("--id", default="114514", action="store", required=False, dest="id", help="Your ID.")
    # file path
    parser.add_argument("--f", default="", action="store", required=False, dest="file",
                        help="File path. Default is empty (no file will be uploaded).")
    return parser.parse_args()


def build_request(req_type, req_operation, req_json, req_bin=None):
    req_json[FIELD_TYPE] = req_type
    req_json[FIELD_OPERATION] = req_operation
    req_json[FIELD_DIRECTION] = DIR_REQUEST
    body_json = json.dumps(dict(req_json), ensure_ascii=False)
    body_length = len(body_json)
    if req_bin is None:
        return struct.pack('!II', body_length, 0) + body_json.encode()
    else:
        return struct.pack('!II', body_length, len(req_bin)) + body_json.encode() + req_bin


def do_receive(conn):
    bin_data = b''
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)

    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data


def do_md5(password):
    hl = hashlib.md5()
    hl.update(password.encode(encoding='utf8'))
    md5 = hl.hexdigest()
    return str(md5)


def do_request(host, port, id, file_path):
    # 建联
    cliSocket = socket(AF_INET, SOCK_STREAM)
    cliSocket.connect((host, port))

    # [LOGIN]
    login_json = {
        FIELD_USERNAME: "114514",  # TODO: use id
        FIELD_PASSWORD: do_md5(id)
    }
    cliSocket.send(build_request(TYPE_AUTH, OP_LOGIN, login_json))

    json_data, bin_data = do_receive(cliSocket)

    token = ''

    if json_data[FIELD_STATUS] == 200:
        token = json_data[FIELD_TOKEN]
        logger.info("Token : {%s}" % token)

    # [SAVE]
    file_name = file_path.split('/')[-1]
    save_json = {
        FIELD_KEY: file_name,
        FIELD_SIZE: os.path.getsize(file_path),
        FIELD_TOKEN: token,
    }
    cliSocket.send(build_request(TYPE_FILE, OP_SAVE, save_json))

    json_data, bin_data = do_receive(cliSocket)

    # [UPLOAD]
    # TODO: use file_path
    file = open("./test.png", 'rb').read()
    file_md5 = hashlib.md5(file)

    block_index = 0
    total_block = json_data[FIELD_TOTAL_BLOCK]
    block_size = json_data[FIELD_BLOCK_SIZE]

    for i in tqdm(range(total_block)):
        upload_json = {
            FIELD_KEY: file_name,
            FIELD_BLOCK_INDEX: block_index,
            FIELD_TOKEN: token,
        }
        content = file[block_size * block_index: block_size * (block_index + 1)]
        cliSocket.send(build_request(TYPE_FILE, OP_UPLOAD, upload_json, content))
        block_index = block_index + 1
        json_data, bin_data = do_receive(cliSocket)

    if file_md5 == str(json_data[FIELD_MD5]):
        logger.info("upload success")
    else:
        logger.info("upload failed")


def main():
    parser = parse_cmd_args()
    isConfirm = input("Do you confirm that you want to send the file: [y/N]")
    if isConfirm == 'y':
        do_request(parser.server_ip, parser.port, parser.id, parser.file)
    elif isConfirm == 'N':
        sys.exit()
    else:
        print("Unvalidated Input, please restart.")


if __name__ == '__main__':
    main()
