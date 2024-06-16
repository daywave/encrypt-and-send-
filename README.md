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

### Instalación de dependencias

```bash
pip install paramiko pycryptodome
sudo apt-get install steghide
