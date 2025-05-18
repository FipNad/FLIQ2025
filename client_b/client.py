import socket
import threading
import subprocess
import ctypes
import requests
import os
import time


client_ip_mapping = {
    "clientA": "172.30.0.2:5000",
    "clientB": "172.30.0.3:5000"
}

authenticated = False
answer_peer_connection = False
to_peer_connection = False
can_ask_seed = True
ask_to_peer_connection = False
started_peer = False

TO_PEER_CONN = None

peer_byte_counters = {}  # (direction) → bytes_sent
MY_ID = None   

HOST = 'host.docker.internal'  # Address of the central server
SERVER_PORT = 12345
LISTEN_PORT = 5000

server_socket = None  # Persistent connection to the server
peer_connections = []  # List of (socket, (ip, port))

seed_AB = "000102030405060708090a0b0c0d03"
seed_BA = ""

def get_memory_address():
    output = subprocess.check_output(['./main'])
    return output.decode()


# ---------------------- Server Communication ----------------------

def connect_to_server():
    global server_socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((HOST, SERVER_PORT))
        print(f"[Client] Connected to server at {HOST}:{SERVER_PORT}")
        threading.Thread(target=listen_to_server, daemon=True).start()
    except Exception as e:
        print(f"[Client] Failed to connect to server: {e}")
        
def authenticate_to_server(user, password, identity):
    global server_socket
    global authenticated
    global MY_ID
    if not authenticated:
        try:
            #password to be hashed before sending
            string = f"AUTHENTICATE_user={user}_password={password}_identity={identity}"

            MY_ID = identity
            authenticated = True
        
            server_socket.sendall(string.encode())
        except Exception as e:
            print(f"[Client] Authentication error: {e}")
    else:
        print("[Client] Already authenticated.")
        
def deauthenticate_to_server():
    global server_socket
    global authenticated
    if authenticated:
        try:
            server_socket.sendall(b"DEAUTHENTICATE")
            authenticated = False
        except Exception as e:
            print(f"[Client] Deauthentication error: {e}")
    else:
        print("[Client] Not authenticated.")


def listen_to_server():
    global authenticated
    global server_socket
    global to_peer_connection
    global answer_peer_connection
    global seed_AB
    global seed_BA

    while True:
        try:
            data = server_socket.recv(65000)
            
            message = data.decode()
            
            if "START DELIVERING QUANTUM SEED" in message:
                print('dadada', flush=True)
                # to_peer_connection = True
                connect_to_peer(client_ip_mapping[TO_PEER_CONN].split(":")[0], int(client_ip_mapping[TO_PEER_CONN].split(":")[1]))
            
            if message.startswith("SEED:"):
                # Extract the seed value from the message
                
                _, raw_seed = message.split("SEED:")
                clean_seed = ''.join(filter(lambda c: c.isdigit() or c == '-' or c == ' ', raw_seed)).strip()
                with seed_lock:
                    seed_AB = clean_seed
                    seed_BA = clean_seed
                to_peer_connection = True
                
            
            message_temp = message.split(':')
            if message_temp[0] == "REQUEST":
                answer_peer_connection = True
            else:
                if not data:
                    break
            print(f"\n[Client] Server: {data.decode()}\n> ", end='', flush=True)
        except Exception:
            break
    print("[Client] Server connection closed.")
    print("[Client] Deauthenticated.")
    authenticated = False


def send_to_server(msg):
    global server_socket
    try:
        server_socket.sendall(msg.encode())
    except Exception as e:
        print(f"[Client] Failed to send to server: {e}")
        
def request_establish_secret(identity):
    global server_socket
    global authenticated
    global ask_to_peer_connection
    global TO_PEER_CONN
    
    if not authenticated:
        print("[Client] Not authenticated. Cannot request connection.")
        return
    try:
        server_socket.sendall(f"REQUEST_CONN_identity={identity}".encode())
        ask_to_peer_connection = True
        TO_PEER_CONN = identity
        print(f"[Client] Requesting secret forming to {identity}")
    except Exception as e:
        print(f"[Client] Failed to request secret forming: {e}")

def accept_to_peer(identity):
    global server_socket
    global authenticated
    global answer_peer_connection
    global TO_PEER_CONN
    try:
        server_socket.sendall(f"ACCEPT_identity={identity}".encode())
        print(f"[Client] Accepting connection to {identity}")
        answer_peer_connection = True
        TO_PEER_CONN = identity
    except Exception as e:
        print(f"[Client] Failed to accept connection: {e}")
        
def request_quantum_seed(Number_of_bytes, direction):
    global server_socket
    global can_ask_seed

    if can_ask_seed:
        try:
            print(f"[Client] Requesting quantum seed for {direction}, {Number_of_bytes} bytes")
            msg = f"REQUEST_SEED_bytes={Number_of_bytes}_direction={direction}"
            server_socket.sendall(msg.encode())
            
        except Exception as e:
            print(f"[Client] Failed to request quantum seed: {e}")
# ---------------------- Peer-to-Peer Communication ----------------------


def listen_for_peers():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", LISTEN_PORT))
        s.listen()
        print(f"[Client] Listening for peers on port {LISTEN_PORT}", flush=True)
        while True:
            conn, addr = s.accept()
            peer_connections.append((conn, addr))
            threading.Thread(target=handle_peer, args=(conn, addr), daemon=True).start()


def handle_peer(conn, addr):
    global seed_AB
    global seed_BA
    global to_peer_connection
    try:
        while True:
            data = conn.recv(65000)
            if data.startswith(b"A-B"):
                _, seed = data.split(b"_")
                print(f"[Client] Received quantum seed for A-B: {seed.decode()}")
                
                print(f"[Client] A-B seed for me: {seed_AB}")
                to_peer_connection = True
            
            elif data.startswith(b"B-A"):
                _, seed = data.split(b"_")
                print(f"[Client] Received quantum seed for B-A: {seed.decode()}")
                
                print(f"[Client] B-A seed for me: {seed_BA}")
            if not data:
                break
            print(f"\n[Client] Received from peer {addr}: {data.decode()}\n> ", end='', flush=True)
    except Exception as e:
        print(f"[Client] Peer {addr} connection error: {e}")
    finally:
        conn.close()
        print(f"[Client] Peer {addr} disconnected.")
        try:
            peer_connections.remove((conn, addr))
        except ValueError:
            pass


def connect_to_peer(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.sendall(b"CONNECTED")  # Optional handshake
        peer_connections.append((s, (ip, int(port))))
        threading.Thread(target=handle_peer, args=(s, (ip, int(port))), daemon=True).start()
        print(f"[Client] Connected to peer {ip}:{port}")
    except Exception as e:
        print(f"[Client] Could not connect to peer: {e}")
        


def send_to_peer(ip, port, direction, msg):
    global seed_AB, seed_BA

    for s, addr in peer_connections:
        if addr == (ip, int(port)):
            try:
                s.sendall(msg.encode())

                # if direction == "A-B":
                #     if len(seed_AB) < len(msg):
                #         print("[Client] Not enough seed_AB bytes. Please request more before sending.")
                #         return
                #     s.sendall(f'{direction}_{seed_AB[0:len(msg)]}'.encode())
                #     print(f"[Client] Sent seed_AB: {seed_AB[0:len(msg)]}", flush=True)
                #     seed_AB = seed_AB[len(msg):]

                # elif direction == "B-A":
                #     if len(seed_BA) < len(msg):
                #         print("[Client] Not enough seed_BA bytes. Please request more before sending.")
                #         return
                #     s.sendall(f'{direction}_{seed_BA[0:len(msg)]}'.encode())
                #     print(f"[Client] Sent seed_BA: {seed_BA[0:len(msg)]}", flush=True)
                #     seed_BA = seed_BA[len(msg):]

                # else:
                #     print("[Client] Invalid direction. Use 'A-B' or 'B-A'.")
                #     return

                print(f"[Client] Sent message and seed to {ip}:{port} in direction {direction}")
                return
            except Exception as e:
                print(f"[Client] Failed to send to peer {ip}:{port} — {e}")
                return

    print(f"[Client] No connection to {ip}:{port}")

def close_peer_connection(ip, port):
    global peer_connections
    for conn, addr in peer_connections:
        if addr == (ip, int(port)):
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass  # Ignore shutdown errors
            conn.close()
            peer_connections.remove((conn, addr))
            print(f"[Client] Closed connection to peer {ip}:{port}")
            return
    print(f"[Client] No active connection to {ip}:{port}")


# ---------------------- Interactive Shell ----------------------

def interactive_shell():
    global answer_peer_connection
    global ask_to_peer_connection
    global to_peer_connection
    global started_peer
    
    
    print("[Client] Commands:")
    print("  server <msg>                       → Send message to server")
    print("  connect <ip> <port>                → Connect to peer ")
    print("  peer <ip> <port> <direction> <msg> → Send message to connected peer")
    print("  close <ip> <port>                  → Close peer connection")
    print("  auth <user> <pass> <identity>      → Authenticate to server")
    print("  deauth                             → Deauthenticate from server")
    print("  request_conn <idendity>            → Request connection to peer")
    print("  accept <identity>                  → Accept peer conn")
    print("  request_seed <bytes> <direction>   → Request quantum seed from server")
    print("  exit                               → Exit the client")

    while True:
        
        try:
            
            
            raw = input("> ").strip()
            
            if raw.lower() == "exit":
                break
            elif raw.startswith("server "):
                msg = raw[len("server "):]
                send_to_server(msg)
            elif raw.startswith("peer "):
                _, ip, port, direction, *msg_parts = raw.split()
                msg = " ".join(msg_parts)
                send_to_peer(ip, int(port), direction, msg)
                
            elif raw.startswith("connect "):
                _, ip, port = raw.split()
                connect_to_peer(ip, int(port))
            elif raw.startswith("auth "):
                _, user, password, identity = raw.split()
                authenticate_to_server(user, password, identity)
            elif raw.startswith("deauth"):
                deauthenticate_to_server()
            elif raw.startswith("request_conn "):
                _, identity = raw.split()
                request_establish_secret(identity)
            elif raw.startswith("request_seed "):
                _, byte_count, direction = raw.split()
                byte_count = int(byte_count)
                request_quantum_seed(byte_count, direction)
            elif raw.startswith("accept "):
                _, identity = raw.split()
                if answer_peer_connection:
                    accept_to_peer(identity)
                    answer_peer_connection = False
                else:
                    print("[Client] No request to accept.")
                
            elif raw.startswith("send "):
                _, ip, port, *msg_parts = raw.split()
                msg = " ".join(msg_parts)
                send_to_peer(ip, int(port), msg)
                
            elif raw.startswith("close "):
                _, ip, port = raw.split()
                close_peer_connection(ip, int(port))
            else:
                print("Invalid command.")
        except Exception as e:
            print(f"[Client] Error: {e}")


# ---------------------- ASLR Memory Management ----------------------
PROT_READ = 0x1
PROT_WRITE = 0x2
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
MAP_FIXED_NOREPLACE = 0x100000  # Linux 4.17+

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

libc = ctypes.CDLL("libc.so.6", use_errno=True)

class QRNGAllocator:
    def __init__(self, base_range=(0x40000000, 0x7FFFFFFF)):
        self.base_min, self.base_max = base_range

    def get_qrng_uint32(self):
        min = -2147483648
        max = 2147483647
        quantity = 1
        try:
            url = f"https://qrng.idqloud.com/api/1.0/int?max={max}&min={min}&quantity={quantity}"
            headers = {
                "X-API-KEY": "aTo4BKRvnc49uRWDk034zaua87vGRXKk9TMLdfkI"
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()["data"][0]
        except Exception as e:
            print(f"[!] QRNG fetch failed, using fallback: {e}")
        return int.from_bytes(os.urandom(4), 'big')

    def align_down(self, addr):
        return addr & ~(PAGE_SIZE - 1)

    def allocate(self, size):
        assert size % PAGE_SIZE == 0, "Size must be page-aligned"

        rnd = self.get_qrng_uint32()
        raw_addr = self.base_min + (rnd % (self.base_max - self.base_min - size))
        aligned_addr = self.align_down(raw_addr)

        addr = libc.mmap(
            ctypes.c_void_p(aligned_addr),
            ctypes.c_size_t(size),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0
        )

        if addr == -1 or addr is None or addr == ctypes.c_void_p(-1).value:
            errno = ctypes.get_errno()
            raise OSError(errno, f"mmap failed at 0x{aligned_addr:x}: {os.strerror(errno)}")

        print(f"[+] Allocated {size} bytes at: 0x{addr:x}")
        return addr

    def free(self, addr, size):
        result = libc.munmap(ctypes.c_void_p(addr), ctypes.c_size_t(size))
        if result != 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        print(f"[-] Freed memory at: 0x{addr:x}")


def qrng_seed_shuffler():
    global to_peer_connection
    allocator = QRNGAllocator()
    size = PAGE_SIZE
    global seed_AB
    time_step = 0

    # print
    
    while True:
        if to_peer_connection:
            print("[Client] QRNG Seed Shuffler active", flush=True)
            try:
                with seed_lock:
                    if not seed_AB:
                        time.sleep(1)
                        continue

                    test = seed_AB.encode()[:PAGE_SIZE]  # truncate to page size
                    addr = allocator.allocate(PAGE_SIZE)
                    ctypes.memmove(addr, test, len(test))
                    shuffled = ctypes.string_at(addr, len(test)).decode(errors='ignore')
                    print("[*] Read from memory:", ctypes.string_at(addr, len(test)).decode())
                    # new_seed = shuffled[::-1]  # example shuffle

                    seed_AB = shuffled[:len(seed_AB)]
                    print(f"Simulated seed {seed_AB}, fount at addr: {addr}", flush=True)

                    allocator.free(addr, PAGE_SIZE)

                time.sleep(2)
            except Exception as e:
                print("[QRNG] Error:", e)
                time.sleep(2)
        else:
            # If not connected, just wait a bit before checking again
            time.sleep(1)


# ---------------------- Entry Point ----------------------
seed_lock = threading.Lock()

if __name__ == "__main__":
    # C CODE TESTING
    # memory_address = get_memory_address()
    # print(f"Memory address: {memory_address}")
    
    print("[Client] Starting...")

    threading.Thread(target=listen_for_peers, daemon=True).start()
    threading.Thread(target=qrng_seed_shuffler, daemon=True).start()
    
    
    time.sleep(1)
    connect_to_server()
    interactive_shell()


    # connect_to_server() -> DONE
    # authenticate_to_server(user, password) -> DONE
    
    #request_communicate_to_user(ip, port)
    "server have to create a secret seed and share to the two clients, if they are connected to server" 
    "return the seed to the clients periodically"
    

    #REQUEST API IDQUANTIQUE -> RANDOM VALUE FOR MEMORY 
    #REQUEST API IDQUANTIQUE -> RANDOM SEED FOR SS
    
    
    # allocator = QRNGAllocator()
    # try:
    #     size = PAGE_SIZE  # Ensure size is page-aligned
    #     test = b"12345678910"
    #     time_stemp = 0
        
    #     while time_stemp < 100:
    #         addr = allocator.allocate(size)

    #         # Optional: write to memory
        
    #         ctypes.memmove(addr, test, len(test))
            
    #         #if started_communication:
    #             #receive_seed_from_server
    #             #save_to_memory
    #             #use as seed
                
    #             #if receive another seed from server
    #             #change seed in use and in memory
            
            
    #         print("[*] Read from memory:", ctypes.string_at(addr, len(test)).decode())
    #         #use for establishing SS 
    #         #simulating transfer on FREQ HOPING // BLE DEVICE

    #         allocator.free(addr, size)
            
    #         time_stemp += 1
    # except Exception as e:
    #     print("Error:", e)
    

    
    
    

    
    
    ##conect_to_server()
