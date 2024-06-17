import socket
import uuid
from Crypto.PublicKey import RSA

# Función para obtener la dirección MAC
def get_mac_address():
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join([mac[i:i+2] for i in range(0, 12, 2)])

# Función para solicitar el nombre del archivo
def get_filename():
    filename = input("Ingrese el nombre del archivo para recibir (sin extensión): ")
    return f"{filename}.txt"

# Generar una clave RSA
key = RSA.generate(2048)
public_key = key.publickey().export_key().decode('utf-8')

# Crear un socket
slave_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = ''  # Aceptar conexiones de cualquier dirección IP
port = 2222  # Puerto de comunicación para sockets
slave_socket.bind((host, port))

# Credenciales para SCP
scp_username = "donovan"
scp_password = "123456789"

# Esperar conexiones
slave_socket.listen(1)
print("Esperando conexiones en el puerto 2222...")

while True:
    # Aceptar una conexión
    conn, addr = slave_socket.accept()
    print(f"Conexión establecida desde: {addr}")

    try:
        while True:
            # Recibir solicitud
            request = conn.recv(1024).decode('utf-8')
            if not request or request == "STOP":
                print("El master ha cerrado la conexión.")
                break
            print(f"Solicitud recibida: {request}")
            if request == "SEND_PUBLIC_KEY":
                # Enviar la clave pública
                conn.send(public_key.encode('utf-8'))
                print("Clave pública enviada.")
                
                # Enviar la dirección MAC
                mac_address = get_mac_address()
                conn.send(mac_address.encode('utf-8'))
                print("Dirección MAC enviada.")
            elif request == "SEND_FILE_REQUEST":
                # Decidir aceptar o rechazar la solicitud
                decision = input("¿Desea aceptar la solicitud de envío de archivo? (yes/no): ")
                if decision.lower() == "yes":
                    conn.send(b"ACCEPT")
                    print("Solicitud de archivo aceptada.")
                    credentials = f"{scp_username}:{scp_password}"
                    conn.send(credentials.encode('utf-8'))
                    print("Credenciales enviadas.")
                    
                    # Solicitar el nombre del archivo para recibir
                    file_path = get_filename()
                    print(f"El archivo se guardará como: {file_path}")

                    # Recibir el conjunto de hashes y la contraseña de steghide
                    hashes_and_password = conn.recv(1024).decode('utf-8')
                    file_hash, encrypted_message_hash, blake2_hash, steghide_password = hashes_and_password.split(':')
                    print(f"Hashes recibidos: SHA-384: {file_hash}, SHA-512: {encrypted_message_hash}, Blake2: {blake2_hash}")
                    print(f"Contraseña de steghide recibida: {steghide_password}")

                    # Recibir el mensaje encriptado
                    encrypted_message = conn.recv(4096)
                    print("Mensaje encriptado recibido.")

                    # Guardar el mensaje encriptado en el archivo especificado
                    with open(file_path, "wb") as file:
                        file.write(encrypted_message)
                    print(f"Mensaje encriptado guardado en {file_path}.")
                else:
                    conn.send(b"REJECT")
                    print("Solicitud de archivo rechazada.")
            else:
                print("Solicitud no reconocida.")
                
    except Exception as e:
        print(f"Error al manejar la solicitud: {e}")
    finally:
        # Cerrar la conexión
        conn.close()
        print("Conexión cerrada por el esclavo.")
