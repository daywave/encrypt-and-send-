import socket
import os
import paramiko
import hashlib
import tkinter as tk
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def send_file_via_scp(username, password, ip, port, file_path, remote_path):  # Function 1
    try:
        transport = paramiko.Transport((ip, port))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(file_path, remote_path)
        sftp.close()
        transport.close()
        print(f"Archivo {file_path} enviado exitosamente a {remote_path}.")
    except paramiko.AuthenticationException as auth_error:
        print(f"Error de autenticación al enviar el archivo {file_path}: {auth_error}")
    except paramiko.SSHException as ssh_error:
        print(f"Error SSH al enviar el archivo {file_path}: {ssh_error}")
    except FileNotFoundError as fnf_error:
        print(f"Archivo no encontrado {file_path}: {fnf_error}")
    except Exception as e:
        print(f"Error al enviar el archivo {file_path}: {e}")

def receive_all(sock):  # Function 2
    data = b''
    while True:
        part = sock.recv(4096)
        data += part
        if len(part) < 4096:
            break
    return data.decode('utf-8')

def select_file():  # Function 3
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    return file_path

def calculate_sha384(file_path):  # Function 4
    sha384_hash = hashlib.sha384()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha384_hash.update(byte_block)
    return sha384_hash.hexdigest()

def calculate_sha512(data):  # Function 5
    sha512_hash = hashlib.sha512()
    sha512_hash.update(data)
    return sha512_hash.hexdigest()

def calculate_blake2(file_path):  # Function 6
    blake2_hash = hashlib.blake2b()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            blake2_hash.update(byte_block)
    return blake2_hash.hexdigest()

def encrypt_message_with_rsa(message, public_key):  # Function 7
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_chunks = []
    chunk_size = rsa_key.size_in_bytes() - 42
    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunk = cipher_rsa.encrypt(chunk.encode('utf-8'))
        encrypted_chunks.append(encrypted_chunk)
    return b''.join(encrypted_chunks)

def get_filename():  # Function 8
    filename = input("Ingrese el nombre del archivo (sin extensión): ")
    return f"{filename}.txt"

def clear_directory(path):  # Function 9
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        if os.path.isfile(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            os.rmdir(file_path)
    print(f"Contenido del directorio {path} eliminado.")

def calculate_file_hash(file_path):  # Function 10
    sha512_hash = hashlib.sha512()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha512_hash.update(byte_block)
    return sha512_hash.hexdigest()

def handle_file_transfer(master_socket, master_path, slave_ip, public_key):  # Function 11
    while True:  # Sub-function 11.1
        option = input("Seleccione una opción (1: Escribir mensaje, 2: Seleccionar archivo, 3: Salir): ")

        if option == "1":  # Sub-function 11.1.1
            message = input("Ingrese el mensaje a enviar: ")
            if message.lower() == "stop":  # Sub-function 11.1.1.1
                master_socket.send(b"STOP")
                print("Conexión cerrada por el master.")
                master_socket.close()
                break
            file_path = os.path.join(master_path, get_filename())
            with open(file_path, "w") as file:
                file.write(message)
            print(f"Archivo {file_path} generado.")
        elif option == "2":  # Sub-function 11.1.2
            file_path = select_file()
            if not file_path:
                print("No se seleccionó ningún archivo.")
                continue
        elif option == "3":  # Sub-function 11.1.3
            master_socket.send(b"STOP")
            print("Conexión cerrada por el master.")
            master_socket.close()
            break
        else:  # Sub-function 11.1.4
            print("Opción inválida.")
            continue

        sha384_path = os.path.join(master_path, "sha384_mensaje_original")  # Sub-function 11.2
        file_hash = calculate_sha384(file_path)
        with open(sha384_path, "w") as file:
            file.write(file_hash)
        print(f"Hash SHA-384 del archivo almacenado en {sha384_path}: {file_hash}")

        with open(file_path, "r") as file:  # Sub-function 11.3
            message = file.read()

        encrypted_message = encrypt_message_with_rsa(message, public_key)  # Sub-function 11.4
        encrypted_path = os.path.join(master_path, "encriptado_con_RSA")
        with open(encrypted_path, "wb") as file:
            file.write(encrypted_message)
        print("Mensaje encriptado con RSA y almacenado en encriptado_con_RSA.")

        os.remove(file_path)  # Sub-function 11.5
        print(f"Archivo sin encriptar {file_path} eliminado.")

        sha512_path = os.path.join(master_path, "sha512_mensaje_encriptado")  # Sub-function 11.6
        encrypted_message_hash = calculate_sha512(encrypted_message)
        with open(sha512_path, "w") as file:
            file.write(encrypted_message_hash)
        print(f"Hash SHA-512 del mensaje encriptado almacenado en {sha512_path}: {encrypted_message_hash}")

        cover_file_path = select_file()  # Sub-function 11.7
        if not cover_file_path:
            print("No se seleccionó ningún archivo para ocultar el mensaje.")
            continue

        steghide_password = input("Ingrese la contraseña para steghide: ")  # Sub-function 11.8
        stego_file_path = os.path.join(master_path, "stego_file")
        os.system(f"steghide embed -cf {cover_file_path} -ef {encrypted_path} -sf {stego_file_path} -p '{steghide_password}'")
        print("Mensaje oculto en el objeto usando steghide.")

        blake2_path = os.path.join(master_path, "blake2_stego")  # Sub-function 11.9
        blake2_hash = calculate_blake2(stego_file_path)
        with open(blake2_path, "w") as file:
            file.write(blake2_hash)
        print(f"Hash Blake2 del archivo con información oculta almacenado en {blake2_path}: {blake2_hash}")

        sha512_hashes = {}  # Sub-function 11.10
        for path in [sha384_path, sha512_path, blake2_path, stego_file_path]:
            sha512_hashes[os.path.basename(path)] = calculate_file_hash(path)

        master_socket.send(b"SEND_FILE_REQUEST")  # Sub-function 11.11
        response = master_socket.recv(1024).decode('utf-8')
        if response == "ACCEPT":
            credentials = receive_all(master_socket)
            username, password = credentials.split(':')
            print(f"Credenciales recibidas - Usuario: {username}, Contraseña: {password}")

            file_paths = [sha384_path, sha512_path, blake2_path, stego_file_path]
            for path in file_paths:
                remote_path = f"/home/{username}/lista/{os.path.basename(path)}"
                send_file_via_scp(username, password, slave_ip, 22, path, remote_path)

            master_socket.send(str(sha512_hashes).encode('utf-8'))

            confirmation = master_socket.recv(1024).decode('utf-8')
            if confirmation == "FILES_RECEIVED":
                master_socket.send(steghide_password.encode('utf-8'))
                print("Contraseña de steghide enviada al esclavo.")
            else:
                print("Error en la recepción de archivos por parte del esclavo.")
        else:
            print("Solicitud rechazada por el esclavo.")

def main():  # Function 12
    master_path = "/home/ddaywave/lista"
    os.makedirs(master_path, exist_ok=True)

    if os.listdir(master_path):
        clear_dir = input(f"El directorio {master_path} no está vacío. ¿Desea vaciarlo antes de continuar? (yes/no): ")
        if clear_dir.lower() == 'yes':
            clear_directory(master_path)
        else:
            print("Proceso detenido por el usuario.")
            exit()

    slave_ip = "192.168.1.67"
    port = 2222

    master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"Intentando conectar con {slave_ip} en el puerto {port}...")

    try:
        master_socket.connect((slave_ip, port))
        print("Conexión establecida.")

        master_socket.send(b"SEND_PUBLIC_KEY")
        public_key = receive_all(master_socket)
        print(f"Clave pública recibida: {public_key}")

        mac_address = receive_all(master_socket)
        print(f"Dirección MAC del esclavo: {mac_address}")

        handle_file_transfer(master_socket, master_path, slave_ip, public_key)

    except ConnectionRefusedError:
        print("Conexión rechazada. Asegúrate de que el esclavo está en ejecución y escuchando en el puerto especificado.")
    except Exception as e:
        print(f"Ocurrió un error: {e}")

if __name__ == "__main__":
    main()
