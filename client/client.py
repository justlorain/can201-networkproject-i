import sys
from socket import *
import json
import os
import argparse  # *

import struct
import time
import logging
from logging.handlers import TimedRotatingFileHandler

from threading import Thread, RLock, Lock

import hashlib
from tqdm import tqdm

# type
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
# operation
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', 'ERROR'
# direction
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'
# other
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'

logger = logging.getLogger('')
return_md5 = ""


def parse_cmd_args():
    # args defined form terminal
    parser = argparse.ArgumentParser()
    # server ip
    parser.add_argument("-server_ip", default="127.0.0.1", action="store", required=False, dest="server_ip",
                        help="The IP address bind to the server. Default bind all IP.")
    # server port
    parser.add_argument("-port", default=1379, action="store", required=False, type=int, dest="port",
                        help="The port that server listen on. Default is 1379")
    # student id
    parser.add_argument("-id", default="114514", action="store", required=False, dest="id", help="Your ID.")
    # file path
    parser.add_argument("-f", default=" ", action="store", required=False, dest="file",
                        help="File path. Default is empty (no file will be uploaded).")
    # num of thread
    parser.add_argument("-num", default="2", action="store", required=False, dest="thread_num",
                        help="The number of the threads. Default is 2")
    return parser.parse_args()


def get_time_based_filename(ext, prefix='', t=None):
    """
    Get a filename based on time
    :param ext: ext name of the filename
    :param prefix: prefix of the filename
    :param t: the specified time if necessary, the default is the current time. Unix timestamp
    :return:
    """
    ext = ext.replace('.', '')
    if t is None:
        t = time.time()
    if t > 4102464500:
        t = t / 1000
    return time.strftime(f"{prefix}%Y%m%d%H%M%S." + ext, time.localtime(t))


def set_logger(logger_name):
    """
    Create a logger
    :param logger_name:
    :return: logger
    """
    logger_ = logging.getLogger(logger_name)  # 不加名称设置root logger
    logger_.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '\033[0;34m%s\033[0m' % '%(asctime)s-%(name)s[%(levelname)s] %(message)s @ %(filename)s[%(lineno)d]',
        datefmt='%Y-%m-%d %H:%M:%S')

    # --> LOG FILE
    logger_file_name = get_time_based_filename('log.log')
    os.makedirs(f'log/{logger_name}', exist_ok=True)

    fh = TimedRotatingFileHandler(filename=f'log/{logger_name}/log.log', when='D', interval=1, backupCount=1)
    fh.setFormatter(formatter)

    fh.setLevel(logging.INFO)

    # --> SCREEN DISPLAY
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    logger_.propagate = False
    logger_.addHandler(ch)
    logger_.addHandler(fh)
    return logger_


def build_request(req_type, req_operation, req_json, req_bin=None):
    """
     Make a request packet following the STEP protocol.
     Any information or data for TCP transmission has to use this function to get the packet.
     :param req_type:
     :param req_operation:
     :param req_json:
     :param req_bin:
     :return: The complete binary packet
     """
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
    """
      Receive and decode the message from server
      :param conn:
      :return: The json part and binary part of massage
      """
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


def get_password(user_name):
    """
    Calculate the md5 of username, as the password
    :param user_name:
    :return:
    """
    hl = hashlib.md5()
    hl.update(user_name.encode(encoding='utf8'))
    md5 = hl.hexdigest()
    return str(md5)


def get_file_md5(filename):
    """
    Get MD5 value for big file
    :param filename:
    :return:
    """
    m = hashlib.md5()
    with open(filename, 'rb') as fid:
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()


lock_send = Lock()
lock_recv = Lock()


def thread_send_block(upload_json, cliSocket, num_each_thread, file, block_size, thread_num, outlier_num, total_thread):
    """
    :param upload_json:
    :param cliSocket:
    :param num_each_thread:
    :param file:
    :param block_size:
    :param thread_num: the index of thread
    :param outlier_num:
    :param total_thread:
    :return:
    """

    global logger, return_md5
    # handle the outliers
    if outlier_num > 0 and thread_num == 0:
        for index in range(outlier_num):
            upload_json[FIELD_BLOCK_INDEX] = (index + num_each_thread * total_thread)
            content = file[block_size * (index + num_each_thread * total_thread): block_size * (
                    index + num_each_thread * total_thread + 1)]
            lock_send.acquire()  # LOCK ON
            cliSocket.send(build_request(TYPE_FILE, OP_UPLOAD, upload_json, content))
            lock_send.release()  # LOCK OFF
            lock_recv.acquire()  # LOCK ON
            json_data, bin_data = do_receive(cliSocket)
            lock_recv.release()  # LOCK OFF
            check_upload_error(json_data, cliSocket, upload_json, content)

    # normal part
    for block_index in tqdm(range(num_each_thread), desc=f"Update progress for thread {thread_num + 1}", unit='block'):
        upload_json[FIELD_BLOCK_INDEX] = (block_index + num_each_thread * thread_num)
        content = file[block_size * upload_json[FIELD_BLOCK_INDEX]: block_size * (
                upload_json[FIELD_BLOCK_INDEX] + 1)]
        lock_send.acquire()  # LOCK ON
        cliSocket.send(build_request(TYPE_FILE, OP_UPLOAD, upload_json, content))
        lock_send.release()  # LOCK OFF
        lock_recv.acquire()  # LOCK ON
        json_data, bin_data = do_receive(cliSocket)
        lock_recv.release()  # LOCK OFF
        check_upload_error(json_data, cliSocket, upload_json, content)


def check_upload_error(json_data,  cliSocket, upload_json, content):
    """
    Detect and handle the error from server when uploading
    :param json_data:
    :param cliSocket:
    :param upload_json:
    :param content:
    :return:
    """
    global logger, return_md5
    if json_data[FIELD_STATUS] == 200:
        if FIELD_MD5 in json_data:
            logger.info(f"--> The whole file '{json_data[FIELD_KEY]}' has been uploaded")
            return_md5 = str(json_data[FIELD_MD5])
    else:
        logger.error(f"--> ERROR, {json_data[FIELD_STATUS]} : '{json_data[FIELD_STATUS_MSG]}' ")
        error_code = json_data[FIELD_STATUS]
        if error_code == 408:
            print("These error should not occur because the key must be accepted and new in this client code.")
            print("Please make a save request once before you upload related file and try again!")
        elif error_code == 410:
            print("These error should not occur because client message has been nicely formatted.")
            print("Please check your code and try again!")
        elif error_code == 405:
            print("Please check your package dividing functions and try again!")
        elif error_code == 406:
            logger.info(
                f"<-- Block error detected, need to re-send the WHOLE FILE"
                f"(This Error may occur because server does not accept multi-thread well). ")
            # TODO report: 测试中发现网络问题不能单个block重传，只能所有一起重传
            # RESEND the whole file
            # check_upload_error(json_data, cliSocket, upload_json, content)
        cliSocket.close()
        print("Mission fail, client close.")
        sys.exit()


def do_login(user_name, cliSocket):
    """
    Execute OP_LOGIN, send request to the server
    :param user_name:
    :param cliSocket:
    :return:
    """
    login_json = {
        FIELD_USERNAME: user_name,
        FIELD_PASSWORD: get_password(user_name)
    }
    logger.info(f'<-- Client login with username : {user_name} and password : {get_password(user_name)}')
    cliSocket.send(build_request(TYPE_AUTH, OP_LOGIN, login_json))
    json_data, bin_data = do_receive(cliSocket)

    if json_data[FIELD_STATUS] == 200:
        token = json_data[FIELD_TOKEN]
        logger.info(f'--> Authorization and login successfully. Token: {token}')
        print(f"Token : {token}")
        return token
    else:
        logger.error(f"--> ERROR, {json_data[FIELD_STATUS]} : '{json_data[FIELD_STATUS_MSG]}' ")
        error_code = json_data[FIELD_STATUS]
        if error_code == 400 or error_code == 407 or error_code == 408 or error_code == 409:
            print("These error should not occur because client message has been nicely formatted.")
            print("Please check your code and try again!")
        elif error_code == 410:
            print("These error should not occur because username has a default value.")
            print("Please check your args code and try again!")
        elif error_code == 401:
            print("These error should not occur because username has a default value.")
            print("Please check your md5-encode code and try again!")
        cliSocket.close()
        print("Mission fail, client close.")
        sys.exit()


def do_save(file_path, cliSocket, token):
    """
    Execute OP_SAVE, send request to the server
    :param file_path:
    :param cliSocket:
    :param token:
    :return:
    """
    # Check the size of file <= 1MB
    if os.path.getsize(file_path) >= 1024 * 1000:
        logger.error(f"ERROR, the size of the file must less than 1MB, but client got {os.path.getsize(file_path)}")
        cliSocket.close()
        print("Mission fail, client close.")
        sys.exit()

    file_name = file_path.split('/')[-1]
    save_json = {
        FIELD_KEY: file_name,  # we define the key as filename.
        FIELD_SIZE: os.path.getsize(file_path),
        FIELD_TOKEN: token,
    }
    cliSocket.send(build_request(TYPE_FILE, OP_SAVE, save_json))
    logger.info(f'<-- Send save request for key "{file_name}" with {save_json[FIELD_SIZE] / 1000} KB ')
    json_data, bin_data = do_receive(cliSocket)

    if json_data[FIELD_STATUS] == 200:
        logger.info(
            f'--> Upload plan received for "key": {json_data[FIELD_KEY]} with total block number {json_data[FIELD_TOTAL_BLOCK]} and block size {json_data[FIELD_BLOCK_SIZE]}.')
        return file_name, json_data, bin_data
    else:
        logger.error(f"--> ERROR, {json_data[FIELD_STATUS]} : '{json_data[FIELD_STATUS_MSG]}' ")
        error_code = json_data[FIELD_STATUS]
        if error_code == 403:
            print("These error should not occur because the code will login before make save request.")
            print("Please login before you make other operations and try again!")
        elif error_code == 402:
            print("Please change a key or use DELETE to delete this key")
        cliSocket.close()
        print("Mission fail, client close.")
        sys.exit()


def do_upload(file_path, file_name, json_data, thread_num, token, cliSocket):
    """
    Execute OP_UPLOAD, send blocks to the server
    :param file_path:
    :param file_name:
    :param json_data:
    :param thread_num: number of threads
    :param token:
    :param cliSocket:
    :return:
    """
    with open(file_path, 'rb') as fid:
        file = fid.read()
    file_md5 = get_file_md5(file_path)
    total_block = json_data[FIELD_TOTAL_BLOCK]
    block_size = json_data[FIELD_BLOCK_SIZE]

    thread_num = int(thread_num)
    num_each_thread = total_block / thread_num
    num_each_thread = int(num_each_thread)
    outlier_num = total_block % thread_num

    if total_block < thread_num:  # if a file is too small that less than 20kb
        thread_num = 1
        num_each_thread = total_block
        outlier_num = 0

    time_before_update = time.time()
    upload_json = {
        FIELD_KEY: file_name,
        FIELD_TOKEN: token,
    }
    threads = []
    for num in range(thread_num):
        try:
            thread = Thread(
                target=thread_send_block,
                args=(upload_json, cliSocket, num_each_thread, file, block_size, num, outlier_num, thread_num))
            thread.start()
            time.sleep(0.02)
            threads.append(thread)
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')

    for thread in threads:
        thread.join()
    time_after_update = time.time()
    update_time = time_after_update - time_before_update
    update_avg_time = update_time / num_each_thread
    logger.info(
        f'<<<UPLOAD cost {round(update_time * 1000)}ms, approximately {round(update_avg_time * 1000)}ms for each '
        f'block>>>')
    os.makedirs("./record", exist_ok=True)

    # # generate record
    # with open("record/record_thread2.txt", 'a') as fid:
    #     size = json_data[FIELD_KEY].split(".png")[0]
    #     content = f"{size},{round(update_time * 1000)},{round(update_avg_time * 1000)}"
    #     fid.write(content + '\n')
    return file_md5


def do_request(host, port, user_name, file_path, thread_num):
    """
    Build connection with server, make authorization
    and make SAVE and UPLOAD request.
    :param host: server ip
    :param port: server port
    :param user_name:
    :param file_path:
    :param thread_num: number of threads
    :return:
    """
    global logger
    cliSocket = socket(AF_INET, SOCK_STREAM)
    cliSocket.connect((host, port))
    logger.info(f'<-- Build the TCP connection with {host} on {port}')
    # cliSocket.settimeout(20)  # if time exceeded 20s, then there is a deadlock due to the network problem

    # [LOGIN]
    token = do_login(user_name, cliSocket)

    # [SAVE]
    file_name, json_data, bin_data = do_save(file_path, cliSocket, token)

    # [UPLOAD]
    file_md5 = do_upload(file_path, file_name, json_data, thread_num, token, cliSocket)

    # Validate md5 of the file
    if file_md5 == return_md5:
        logger.info("The md5 of files are match, the server received the right file")
    else:
        logger.error("The md5 of files are not match, the server received a file but not the right file")
    cliSocket.close()
    logger.info("Client close the connection.")


def main():
    global logger
    logger = set_logger('STEP')
    parser = parse_cmd_args()
    # generate record
    # root = os.listdir('./')
    # for file in root:
    #     if file != 'client.py' and file != 'log' and file != 'record':
    #         file = os.path.join('./', file)
    #         do_request(parser.server_ip, parser.port, parser.id, file, 2)
    #     else:
    #         continue
    do_request(parser.server_ip, parser.port, parser.id, parser.file, parser.thread_num)


if __name__ == '__main__':
    main()
