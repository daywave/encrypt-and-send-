import socket
import os
import paramiko
import hashlib
import tkinter as tk
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def send_file_via_scp(username, password, ip, port, file_path, remote_path):
    try:
        transport = paramiko.Transport((ip, port))
        transport.connect(username=username, password=password)

        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(file_path, remote_path)

        sftp.close()
        transport.close()
        print("Archivo enviado exitosamente.")
    except Exception as e:
        print(f"Error al enviar el archivo: {e}")

def receive_all(sock):
    data = b''
    while True:
        part = sock.recv(4096)
        data += part
        if len(part) < 4096:
            break
    return data.decode('utf-8')

def select_file():
    root = tk.Tk()
    root.withdraw()  # Oculta la ventana principal de Tkinter
    file_path = filedialog.askopenfilename()
    return file_path

def calculate_sha384(file_path):
    sha384_hash = hashlib.sha384()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha384_hash.update(byte_block)
    return sha384_hash.hexdigest()

def calculate_sha512(data):
    sha512_hash = hashlib.sha512()
    sha512_hash.update(data)
    return sha512_hash.hexdigest()

def calculate_blake2(file_path):
    blake2_hash = hashlib.blake2b()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            blake2_hash.update(byte_block)
    return blake2_hash.hexdigest()

def encrypt_message_with_rsa(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_chunks = []
    chunk_size = rsa_key.size_in_bytes() - 42  # Ajustar según el padding OAEP

    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunk = cipher_rsa.encrypt(chunk.encode('utf-8'))
        encrypted_chunks.append(encrypted_chunk)

    return b''.join(encrypted_chunks)

# IP del esclavo
slave_ip = "192.168.1.66"  # Sustituye esta cadena por la IP correspondiente
port = 2222  # Puerto de comunicación para sockets

# Crear un socket
master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print(f"Intentando conectar con {slave_ip} en el puerto {port}...")

try:
    # Conectar con el esclavo
    master_socket.connect((slave_ip, port))
    print("Conexión establecida.")

    while True:
        # Solicitar la llave pública
        master_socket.send(b"SEND_PUBLIC_KEY")

        # Recibir la llave pública
        public_key = receive_all(master_socket)
        print(f"Clave pública recibida: {public_key}")

        # Recibir la dirección MAC del esclavo
        mac_address = receive_all(master_socket)
        print(f"Dirección MAC del esclavo: {mac_address}")

        # Seleccionar opción: escribir mensaje o seleccionar archivo
        option = input("Seleccione una opción (1: Escribir mensaje, 2: Seleccionar archivo, 3: Salir): ")

        if option == "1":
            # Capturar un mensaje
            message = input("Ingrese el mensaje a enviar: ")
            if message.lower() == "stop":
                master_socket.send(b"STOP")
                print("Conexión cerrada por el master.")
                master_socket.close()
                break

            # Generar archivo mensaje.txt
            file_path = "mensaje.txt"
            with open(file_path, "w") as file:
                file.write(message)
            print("Archivo mensaje.txt generado.")
        elif option == "2":
            # Seleccionar un archivo para enviar
            file_path = select_file()
            if not file_path:
                print("No se seleccionó ningún archivo.")
                continue
        elif option == "3":
            master_socket.send(b"STOP")
            print("Conexión cerrada por el master.")
            master_socket.close()
            break
        else:
            print("Opción inválida.")
            continue

        # Calcular el hash SHA-384 del archivo
        file_hash = calculate_sha384(file_path)
        print(f"Hash SHA-384 del archivo: {file_hash}")

        # Leer el contenido del archivo
        with open(file_path, "r") as file:
            message = file.read()

        # Cifrar el mensaje con RSA invertido
        encrypted_message = encrypt_message_with_rsa(message, public_key)
        print("Mensaje encriptado con RSA.")

        # Generar el hash SHA-512 del mensaje encriptado
        encrypted_message_hash = calculate_sha512(encrypted_message)
        print(f"Hash SHA-512 del mensaje encriptado: {encrypted_message_hash}")

        # Seleccionar un objeto para esconder el mensaje
        cover_file_path = select_file()
        if not cover_file_path:
            print("No se seleccionó ningún archivo para ocultar el mensaje.")
            continue

        # Solicitar la contraseña para steghide
        steghide_password = input("Ingrese la contraseña para steghide: ")

        # Usar steghide para ocultar el mensaje en el objeto
        stego_file_path = "stego_file"
        os.system(f"steghide embed -cf {cover_file_path} -ef {file_path} -sf {stego_file_path} -p '{steghide_password}'")
        print("Mensaje oculto en el objeto usando steghide.")

        # Calcular el hash Blake2 del archivo con la información oculta
        blake2_hash = calculate_blake2(stego_file_path)
        print(f"Hash Blake2 del archivo con información oculta: {blake2_hash}")

        # Enviar solicitud de envío de archivo
        master_socket.send(b"SEND_FILE_REQUEST")

        # Recibir respuesta de la solicitud
        response = master_socket.recv(1024).decode('utf-8')
        if response == "ACCEPT":
            # Recibir credenciales usando la nueva función
            credentials = receive_all(master_socket)
            username, password = credentials.split(':')
            print(f"Credenciales recibidas - Usuario: {username}, Contraseña: {password}")

            # Enviar los hashes y la contraseña de steghide al esclavo
            hashes_and_password = f"{file_hash}:{encrypted_message_hash}:{blake2_hash}:{steghide_password}"
            master_socket.send(hashes_and_password.encode('utf-8'))
            print("Hashes y contraseña de steghide enviados al esclavo.")

            # Enviar el mensaje encriptado al esclavo
            master_socket.send(encrypted_message)
            print("Mensaje encriptado enviado al esclavo.")

            # Enviar archivo mediante SCP
            remote_path = f"/home/{username}/mensaje_recibido{os.path.splitext(stego_file_path)[1]}"
            send_file_via_scp(username, password, slave_ip, 22, stego_file_path, remote_path)
        else:
            print("Solicitud rechazada por el esclavo.")

except ConnectionRefusedError:
    print("Conexión rechazada. Asegúrate de que el esclavo está en ejecución y escuchando en el puerto especificado.")
except Exception as e:
    print(f"Ocurrió un error: {e}")
