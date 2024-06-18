import socket
import uuid
import paramiko
import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Función para obtener la dirección MAC
def get_mac_address():
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join([mac[i:i+2] for i in range(0, 12, 2)])

# Función para recibir un archivo vía SCP
def receive_file_via_scp(username, password, ip, port, remote_path, local_path):
    try:
        transport = paramiko.Transport((ip, port))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.get(remote_path, local_path)
        sftp.close()
        transport.close()
        print(f"Archivo {remote_path} recibido exitosamente y almacenado en {local_path}.")
    except paramiko.AuthenticationException as auth_error:
        print(f"Error de autenticación al recibir el archivo {remote_path}: {auth_error}")
    except paramiko.SSHException as ssh_error:
        print(f"Error SSH al recibir el archivo {remote_path}: {ssh_error}")
    except FileNotFoundError as fnf_error:
        print(f"Archivo no encontrado {remote_path}: {fnf_error}")
    except Exception as e:
        print(f"Error al recibir el archivo {remote_path}: {e}")

def calculate_blake2(file_path):
    blake2_hash = hashlib.blake2b()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            blake2_hash.update(byte_block)
    return blake2_hash.hexdigest()

def calculate_sha512(file_path):
    sha512_hash = hashlib.sha512()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha512_hash.update(byte_block)
    return sha512_hash.hexdigest()

def calculate_sha384(file_path):
    sha384_hash = hashlib.sha384()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha384_hash.update(byte_block)
    return sha384_hash.hexdigest()

def decrypt_message_with_rsa(encrypted_message, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_chunks = []
    chunk_size = rsa_key.size_in_bytes()
    for i in range(0, len(encrypted_message), chunk_size):
        chunk = encrypted_message[i:i + chunk_size]
        decrypted_chunk = cipher_rsa.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)
    return b''.join(decrypted_chunks).decode('utf-8')

def clear_directory(path):
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        if os.path.isfile(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            os.rmdir(file_path)
    print(f"Contenido del directorio {path} eliminado.")

def calculate_file_hash(file_path):
    sha512_hash = hashlib.sha512()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha512_hash.update(byte_block)
    return sha512_hash.hexdigest()

def handle_request(conn, addr, public_key, private_key, slave_path, scp_username, scp_password):
    try:
        while True:
            request = conn.recv(1024).decode('utf-8')
            if not request or request == "STOP":
                print("El master ha cerrado la conexión.")
                break
            print(f"Solicitud recibida: {request}")
            if request == "SEND_PUBLIC_KEY":
                conn.send(public_key.encode('utf-8'))
                print("Clave pública enviada.")
                mac_address = get_mac_address()
                conn.send(mac_address.encode('utf-8'))
                print(f"Dirección MAC enviada: {mac_address}")
            elif request == "SEND_FILE_REQUEST":
                if os.listdir(slave_path):
                    clear_dir = input(f"El directorio {slave_path} no está vacío. ¿Desea vaciarlo antes de continuar? (yes/no): ")
                    if clear_dir.lower() == 'yes':
                        clear_directory(slave_path)
                    else:
                        print("Proceso detenido por el usuario.")
                        conn.send(b"REJECT")
                        continue
                
                decision = input("¿Desea aceptar la solicitud de envío de archivo? (yes/no): ")
                if decision.lower() == "yes":
                    conn.send(b"ACCEPT")
                    print("Solicitud de archivo aceptada.")
                    credentials = f"{scp_username}:{scp_password}"
                    conn.send(credentials.encode('utf-8'))
                    print("Credenciales enviadas.")

                    file_names = ["sha384_mensaje_original", "sha512_mensaje_encriptado", "blake2_stego", "stego_file"]
                    received_files = []
                    for file_name in file_names:
                        remote_path = f"/home/{scp_username}/lista/{file_name}"
                        local_path = os.path.join(slave_path, file_name)
                        try:
                            receive_file_via_scp(scp_username, scp_password, addr[0], 22, remote_path, local_path)
                            received_files.append(local_path)
                        except Exception as e:
                            print(f"Error al recibir el archivo {file_name}: {e}")
                            conn.send(f"ERROR: {e}".encode('utf-8'))
                            break
                    else:
                        received_hashes = eval(conn.recv(4096).decode('utf-8'))

                        for file_name, expected_hash in received_hashes.items():
                            local_path = os.path.join(slave_path, file_name)
                            calculated_hash = calculate_file_hash(local_path)
                            if expected_hash != calculated_hash:
                                print(f"Error: El hash del archivo {file_name} no coincide. Eliminando mensaje.")
                                clear_directory(slave_path)
                                conn.send("ERROR: Hash no coincide".encode('utf-8'))
                                break
                        else:
                            conn.send(b"FILES_RECEIVED")
                            steghide_password = conn.recv(1024).decode('utf-8')
                            print(f"Contraseña de steghide recibida: {steghide_password}")

                            print("Validando hash Blake2 del stegobjeto...")
                            blake2_received = None
                            with open(os.path.join(slave_path, "blake2_stego"), "r") as file:
                                blake2_received = file.read().strip()

                            blake2_calculated = calculate_blake2(os.path.join(slave_path, "stego_file"))
                            if blake2_received != blake2_calculated:
                                print("Comunicación alterada. Eliminando mensaje.")
                                os.remove(os.path.join(slave_path, "stego_file"))
                                os.remove(os.path.join(slave_path, "blake2_stego"))
                                conn.send("ERROR: Comunicación alterada".encode('utf-8'))
                                break
                            else:
                                print("Hash Blake2 validado correctamente. Comunicación no alterada.")
                                conn.send("SUCCESS: Comunicación validada".encode('utf-8'))

                            print("Extrayendo el mensaje del stegobjeto...")
                            os.system(f"steghide extract -sf {os.path.join(slave_path, 'stego_file')} -p '{steghide_password}' -xf {os.path.join(slave_path, 'extracted_message')}")

                            # Aquí ya no necesitamos el tamaño original del archivo, simplemente extraemos el mensaje
                            with open(os.path.join(slave_path, "extracted_message"), "rb") as file:
                                message = file.read()

                            with open(os.path.join(slave_path, "encriptado_con_RSA"), "wb") as file:
                                file.write(message)
                            print("Mensaje extraído del stegobjeto.")
                            os.remove(os.path.join(slave_path, "stego_file"))
                            print("Stegobjeto eliminado.")

                            print("Validando hash SHA-512 del mensaje encriptado...")
                            sha512_received = None
                            with open(os.path.join(slave_path, "sha512_mensaje_encriptado"), "r") as file:
                                sha512_received = file.read().strip()

                            sha512_calculated = calculate_sha512(os.path.join(slave_path, "encriptado_con_RSA"))
                            if sha512_received != sha512_calculated:
                                print("Error: El hash SHA-512 no coincide. Eliminando mensaje.")
                                os.remove(os.path.join(slave_path, "encriptado_con_RSA"))
                                os.remove(os.path.join(slave_path, "sha512_mensaje_encriptado"))
                                conn.send("ERROR: Hash SHA-512 no coincide".encode('utf-8'))
                                break
                            else:
                                print("Hash SHA-512 validado correctamente.")

                            print("Desencriptando el mensaje con la llave privada...")
                            with open(os.path.join(slave_path, "encriptado_con_RSA"), "rb") as file:
                                encrypted_message = file.read()

                            decrypted_message = decrypt_message_with_rsa(encrypted_message, private_key)
                            with open(os.path.join(slave_path, "mensaje_descifrado.txt"), "w") as file:
                                file.write(decrypted_message)
                            print("Mensaje desencriptado y almacenado en mensaje_descifrado.txt.")

                            print("Validando hash SHA-384 del mensaje desencriptado...")
                            sha384_received = None
                            with open(os.path.join(slave_path, "sha384_mensaje_original"), "r") as file:
                                sha384_received = file.read().strip()

                            sha384_calculated = calculate_sha384(os.path.join(slave_path, "mensaje_descifrado.txt"))
                            if sha384_received != sha384_calculated:
                                print("Error: El hash SHA-384 no coincide. Eliminando mensaje.")
                                os.remove(os.path.join(slave_path, "mensaje_descifrado.txt"))
                                os.remove(os.path.join(slave_path, "sha384_mensaje_original"))
                                conn.send("ERROR: Hash SHA-384 no coincide".encode('utf-8'))
                                break
                            else:
                                print("Hash SHA-384 validado correctamente. El mensaje es seguro.")
                                print("Mensaje recibido y verificado exitosamente.")
                                conn.send("SUCCESS: Mensaje verificado".encode('utf-8'))

                                with open(os.path.join(slave_path, "mensaje_descifrado.txt"), "r") as file:
                                    original_message = file.read()
                                print("Mensaje original recuperado:")
                                print(original_message)
                else:
                    conn.send(b"REJECT")
                    print("Solicitud de archivo rechazada.")
            else:
                print("Solicitud no reconocida.")
    except Exception as e:
        print(f"Error al manejar la solicitud: {e}")
    finally:
        conn.close()
        print("Conexión cerrada por el esclavo.")

def main():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    slave_path = "/home/donovan/lista"
    os.makedirs(slave_path, exist_ok=True)
    slave_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = ''
    port = 2222
    slave_socket.bind((host, port))
    scp_username = "donovan"
    scp_password = "donovan"
    slave_socket.listen(1)
    print("Esperando conexiones en el puerto 2222...")

    while True:
        conn, addr = slave_socket.accept()
        print(f"Conexión establecida desde: {addr}")
        handle_request(conn, addr, public_key, private_key, slave_path, scp_username, scp_password)

if __name__ == "__main__":
    main()
