# Encrypt and Send

Este proyecto proporciona una manera de enviar mensajes cifrados y archivos a través de una red utilizando RSA, hashes y esteganografía. 

## Funcionalidades

1. **Cifrado RSA**: Utiliza RSA para cifrar mensajes.
2. **Generación de hashes**: Calcula hashes SHA-384, SHA-512 y Blake2 de los mensajes y archivos.
3. **Esteganografía**: Oculta mensajes en archivos usando `steghide`.
4. **Transferencia de archivos**: Envía archivos utilizando SCP.
5. **Conexión persistente**: Mantiene la conexión activa hasta que se reciba una instrucción de detener.

## Requisitos

- Python 3
- `paramiko` (para SCP)
- `pycryptodome` (para RSA)
- `steghide` (para esteganografía)

## Instalación

1. Clona este repositorio:
    ```bash
    git clone <URL_del_repositorio>
    ```
2. Instala las dependencias necesarias:
    ```bash
    pip install paramiko tk pycryptodome
    ```
3. Asegúrate de tener `steghide` instalado en tu sistema. En Ubuntu, puedes instalarlo con:
    ```bash
    sudo apt-get install steghide
    ```

## Uso

1. Ejecuta el script principal:
    ```bash
    python master.py
    python slave.py
    ```
2. Sigue las instrucciones en la interfaz para transferir archivos, encriptar mensajes y ocultar información.

## Autores

- Donovan Jerez Ceja
- Jacqueline Renovato Ramirez
- Fernanda Fabiola Delgado Ramirez
- 
# Universidad Autónoma de Aguascalientes
