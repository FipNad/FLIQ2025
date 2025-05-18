import socket
import threading
import time
import requests

HOST = '0.0.0.0'
PORT = 12345

USERS = {
    "filip": "1234",
    "cristi": "1234"
}

LOGGED_IN_USERS = {}

ACTUAL_CONNS = {}

USERS_IDENTIFIER = {}

COMMUNICATIONS_PAIR = {
    
}



# print('TESTTEST')
def handle_client(conn, addr):
    global LOGGED_IN_USERS
    global USERS_IDENTIFIER
    global ACTUAL_CONNS
    global USERS
    
    
    CURRENT_IDENTIFIER = None
    
    print(f"[Server] Connected by {addr}", flush=True)
    try:
        while True:
            data = conn.recv(65000)
            if not data:
                break  # Client disconnected
            msg = data.decode().strip()
            print(f"[Server] Received from {addr}: {msg}", flush=True)

            # Example command handler
            msg_temp = msg.split('_')
            if msg_temp[0] == "AUTHENTICATE":
                # TO VERIFY HASH
                msg_user = msg_temp[1].split('=')[1]
                msg_pass = msg_temp[2].split('=')[1]
                msg_identity = msg_temp[3].split('=')[1]
                print(f"[Server] Authentication attempt for {msg_user}", flush=True)
                # print(f"{msg_user in USERS}, {USERS[msg_user] == msg_pass}", flush=True)
                if msg_user in USERS and USERS[msg_user] == msg_pass:
                    response = "AUTH: OK"
                    print(LOGGED_IN_USERS, flush=True)
                    LOGGED_IN_USERS[msg_user] = addr
                    USERS_IDENTIFIER[msg_identity] = addr
                    CURRENT_IDENTIFIER = msg_identity
                    ACTUAL_CONNS[addr] = conn
                    print(LOGGED_IN_USERS, flush=True)
                    print(f"[Server] Authentication successful for {msg_user}", flush=True)
                    
                else:
                    response = "AUTH: FAIL"
                    print(f"[Server] Authentication failed for {msg_user}", flush=True)
                    
                            
            elif msg_temp[0] == "REQUEST" and msg_temp[1] == "CONN":
                req_user_identity = msg_temp[2].split('=')[1]
                # check if the idtity is in users_identifier
                COMMUNICATIONS_PAIR[CURRENT_IDENTIFIER] = req_user_identity
                
                print(f"[Server] Requested user identity: {req_user_identity}", flush=True)
                if req_user_identity in USERS_IDENTIFIER:
                    print(f"[Server] Requested user is logged in", flush=True)
                    response = "REQUESTED USER IS LOGGED IN"
                    
                    
                    addr_req = USERS_IDENTIFIER[req_user_identity]
                    conn_requested = ACTUAL_CONNS[addr_req]
                    conn_requested.sendall(f"REQUEST: DO YOU WANT TO PARTICIPATE IN CONN with {CURRENT_IDENTIFIER}?".encode())
                    
                else:
                    print(f"[Server] Requested user is not logged in", flush=True)
                    response = "REQUESTED USER IS NOT LOGGED IN"
            
            
            elif msg_temp[0] == "REQUEST" and "SEED" in msg_temp[1]:
                print(f"[Server] Received quantum seed request", flush=True)
                byte_count = int(msg_temp[2].split('=')[1])
                direction = msg_temp[3].split('=')[1]
                print(f"[Server] Received quantum seed request: {byte_count} bytes for direction {direction} from {CURRENT_IDENTIFIER}", flush=True)

                # Simulate seed
                # quantum_seed = os.urandom(byte_count).hex()
                
                # print(f"[Server] Generating quantum seed", flush=True)
                
                
                min = 0
                max = 2**(31) - 1
                quantity = 1
                url = f"https://qrng.idqloud.com/api/1.0/int?max={max}&min={min}&quantity={quantity}"
                headers = {
                    "X-API-KEY": "aTo4BKRvnc49uRWDk034zaua87vGRXKk9TMLdfkI"
                }
                
                count = 0
                seed = ""
                while count < byte_count:
                    try:
                        qrng_response = requests.get(url, headers=headers)
                        if qrng_response.status_code == 200:
                            number = str(qrng_response.json()['data'][0])
                            seed += number
                            count += 1
                        else:
                            print(f"[Server] QRNG fetch failed with status {qrng_response.status_code}")
                    except Exception as e:
                        print(f"[Server] Exception while fetching seed: {e}")
                
                
                # seed = "1234567890"
                # quantum_seed_AB = "12345678910"
                # quantum_seed_BA = "0987654321"
                # print(f'{CURRENT_IDENTIFIER}')
                # print(f'{COMMUNICATIONS_PAIR[CURRENT_IDENTIFIER]}')
                addr1 = USERS_IDENTIFIER['clientA']
                addr2 = USERS_IDENTIFIER['clientB']
                conn1 = ACTUAL_CONNS[addr1]
                conn2 = ACTUAL_CONNS[addr2]
                conn1.sendall(f"SEED:{seed}".encode())
                conn2.sendall(f"SEED:{seed}".encode())
                # conn.sendall(f"SEED:{seed}".encode())

                # Identify both ends from the directi
            
            
            
            
            
            
            elif msg_temp[0] == "ACCEPT":
                accept_user_identity = msg_temp[1].split('=')[1]
                print(f"[Server] Accepting user identity: {accept_user_identity}", flush=True)
                ## CHECK if there is the pair accept_user_identity and CURRENT_IDENTIFIER in COMMUNICATIONS_PAIR, one way or another
                flag = None
                if accept_user_identity in COMMUNICATIONS_PAIR and COMMUNICATIONS_PAIR[accept_user_identity] == CURRENT_IDENTIFIER:
                    # flag  = 1
                    addr1 = USERS_IDENTIFIER[CURRENT_IDENTIFIER]
                    addr2 = USERS_IDENTIFIER[accept_user_identity]
                    conn1 = ACTUAL_CONNS[addr1]
                    conn2 = ACTUAL_CONNS[addr2]
                    conn1.sendall(f"START_{accept_user_identity}".encode())
                    conn2.sendall(f"START_{CURRENT_IDENTIFIER}".encode())
                    
                    
                    response = "START DELIVERING QUANTUM SEED"   
                    conn2.sendall(f"START DELIVERING QUANTUM SEED".encode())
                    
                    
                if CURRENT_IDENTIFIER in COMMUNICATIONS_PAIR and COMMUNICATIONS_PAIR[CURRENT_IDENTIFIER] == accept_user_identity:
                    # flag = 2
                    addr1 = USERS_IDENTIFIER[CURRENT_IDENTIFIER]
                    addr2 = USERS_IDENTIFIER[accept_user_identity]
                    conn1 = ACTUAL_CONNS[addr1]
                    conn2 = ACTUAL_CONNS[addr2]
                    conn1.sendall(f"START_{accept_user_identity}".encode())
                    conn2.sendall(f"START_{CURRENT_IDENTIFIER}".encode())
                    response = "START DELIVERING QUANTUM SEED"
                    conn2.sendall(f"START DELIVERING QUANTUM SEED".encode())
                    
               
            
            
            
            else:
                if msg == "DEAUTHENTICATE":
                    # Deauthenticate the user
                    for user, user_addr in LOGGED_IN_USERS.items():
                        for id, addr_id in USERS_IDENTIFIER.items():
                            if user_addr == addr and addr_id == addr:
                                del LOGGED_IN_USERS[user]
                                del USERS_IDENTIFIER[id]
                                del ACTUAL_CONNS[addr]
                                CURRENT_IDENTIFIER = None
                            
                                response = f"DEAUTH: OK {user}"
                                print(LOGGED_IN_USERS, flush=True)
                                print(f"[Server] Deauthenticated {user}", flush=True)
                                print(LOGGED_IN_USERS, flush=True)
                                break
                        
                elif msg == "ping":
                    response = "pong"
                elif msg == "hello":
                    response = f"Hi client {addr[1]}!"
                else:
                    response = f"Echo: {msg}"
                

            conn.sendall(response.encode())

    except Exception as e:
        print(f"[Server] Error with {addr}: {e}", flush=True)
    finally:
        conn.close()
        
        print(LOGGED_IN_USERS, flush=True)
        print(USERS_IDENTIFIER, flush=True)
        print(ACTUAL_CONNS, flush=True)
        
        for user, user_addr in LOGGED_IN_USERS.items():
            for id, addr_id in USERS_IDENTIFIER.items():
                if user_addr == addr and addr_id == addr:
                    del LOGGED_IN_USERS[user]
                    del USERS_IDENTIFIER[id]
                    del ACTUAL_CONNS[addr]
                    CURRENT_IDENTIFIER = None
                
                    print(f"[Server] Deauthenticated {user}", flush=True)
                    break


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[Server] Listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, addr = s.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()