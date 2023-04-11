from socket import *
import json
import os
import argparse
import struct
import uuid
import hashlib

import time


MAX_PACKET_SIZE=20480

#Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

#copy from server
def make_packet(json_data, bin_data=None):
    #Receive the sftp packet method and parse it into json format data
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data

#request packet copy from server
def make_request_packet(operation, data_type, json_data, bin_data=None):
    """
       Make a packet for response
       :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
       :param status_code: 200 or 400+
       :param data_type: [FILE, DATA, AUTH]
       :param status_msg: A human-readable status massage
       :param json_data
       :param bin_data
       :return:
       """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_TYPE] = data_type
    return make_packet(json_data, bin_data)

#copy from server
def get_tcp_packet(conn):
    """
       Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
       :param conn: the TCP connection
       :return:
           json_data
           bin_data
       """
    bin_data = b'' #null information
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


def login(client_socket, id):
    password = hashlib.md5(id.encode()).hexdigest()
    user_data = {
        "username": id,
        "password": password,
    }
    #send the request packet to the server
    client_socket.send(make_request_packet(OP_LOGIN, TYPE_AUTH, user_data))
    json_data, bin_data = get_tcp_packet(client_socket)
    return json_data #the token value is generally placed in the response data of the login interface and needs to be extracted.

#file upload packet
def fileUploadPacket(operation, data_type,file_size, file_key, token, block_index, json_data, bin_data):
    """
        Make a packet for fileRequest
        :param file_size
        :param block_index
        :param token
        :param file_key:
        :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
        :param data_type: [FILE, DATA, AUTH]
        :param json_data
        :param bin_data
        :return:
        """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_TYPE] = data_type
    json_data[FIELD_KEY] = file_key
    json_data[FIELD_SIZE] = file_size
    json_data[FIELD_TOKEN] = token
    json_data[FIELD_BLOCK_INDEX] = block_index
    return make_packet(json_data, bin_data)


def uploadFile(client_socket, filePath, token):
    file_size = os.path.getsize(filePath)
    #file_key = str(uuid.uuid4())+os.path.basename(filePath) # use uuid to ensure that unique file names are generated
    file_key =os.path.basename(filePath)
    #send the file upload packet to the server
    client_socket.send(fileUploadPacket(OP_SAVE, TYPE_FILE, file_size, file_key, token, None, {}, None))
    json_data, bin_data1 = get_tcp_packet(client_socket)
    total_block = json_data["total_block"]
    block_size = MAX_PACKET_SIZE
    block_index = 0
    #upload one by one
    while block_index < total_block:
        f = open(filePath, 'rb')
        f.seek(block_size*block_index)
        bin_data = f.read(block_size)
        f.close()
        client_socket.send(
            fileUploadPacket(OP_UPLOAD, TYPE_FILE, file_size, file_key, token, block_index, {}, bin_data))
        json_data, bin_data2 = get_tcp_packet(client_socket)
        block_index = block_index+1
        print(json_data)
    return file_key

#Use the get operation to obtain the md5 value of the uploaded file from the server
def get_server_file_md5(client_socket, file_key, token):
    client_socket.send(
        fileUploadPacket(OP_GET, TYPE_FILE, None, file_key, token, None, {}, None))
    json_data, bin_data = get_tcp_packet(client_socket)
    print(json_data)
    return json_data["md5"]

#copy from server Get the md5 value of the file itself
def get_file_md5(filePath):
    """
        Get MD5 value for big file
        :param filePathe:
        :return:
        """
    m = hashlib.md5()
    with open(filePath, 'rb') as fid:
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()


#copy from server
def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--server_ip", default='127.0.0.1', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind all IP.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    parse.add_argument("--id", default='2034172', action='store', required=False, dest="id",
                       help="My ID")
    parse.add_argument("--f", default='', action='store', required=False, dest="f",
                       help="File path. Default is empty (no file will be uploaded)")
    return parse.parse_args()


def main():
    start = time.time()
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port
    file_path = parser.f
    id = parser.id
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((server_ip, int(server_port)))
    json_data = login(client_socket, id)
    # print(json_data)
    file_key = uploadFile(client_socket, file_path, json_data["token"])
    md5 = get_server_file_md5(client_socket, file_key, json_data["token"])
    print(json_data["token"])
    if md5 == get_file_md5(file_path):
        print("upload successfully")
    end = time.time()
    print("upload time：{}".format(end - start))
    client_socket.close()


if __name__ == '__main__':
    main()





