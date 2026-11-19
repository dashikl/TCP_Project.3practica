import socket
import threading
import json

from crypto import xor_encrypt, xor_decrypt


HOST = "127.0.0.1"

NAME = "Client1"


with open("clients.json", "r", encoding="utf-8") as file:
    clients = json.load(file)

with open("network.json", "r", encoding="utf-8") as file:
    network = json.load(file)


info = clients[NAME]
router = info["router"]
PORT = network["routers"][router]["tcp_port"]

key = input("Введите ключ шифрования: ")

if key == "":
    print("Ключ не может быть пустым.")
    raise SystemExit


client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)


client_socket.connect((HOST, PORT))


client_socket.send(
    f"SRP|REGISTER|{NAME}\n".encode("utf-8")
)


def show_incoming(message):
    parts = message.split("|", 7)

    if len(parts) == 8 and parts[1] == "DATA":
        source = parts[2]
        priority = parts[5]
        encrypted = parts[6]
        payload = parts[7]

        print()
        print(f"[{priority}] Сообщение от {source}")
        print("Зашифрованные данные:", payload)

        if encrypted == "1":
            try:
                print("Расшифрованное сообщение:", xor_decrypt(payload, key))
            except ValueError:
                print("Не удалось расшифровать сообщение: неверный ключ.")
        else:
            print("Сообщение:", payload)
    else:
        print()
        print(message)


def receive_messages():
    reader = client_socket.makefile("r", encoding="utf-8")

    try:
        for line in reader:
            line = line.strip()

            if line:
                show_incoming(line)
    except OSError:
        pass


receiver = threading.Thread(
    target=receive_messages,
    daemon=True
)

receiver.start()

print(f"Клиент {NAME} (TCP) подключается к {router}, порт {PORT}")


while True:

    target = input("Получатель (exit - выход): ").strip()

    if target.lower() == "exit":
        break

    if target not in clients:
        print("Неизвестный получатель.")
        continue

    priority = input(
        "Приоритет (NORMAL/HIGH): "
    ).upper()

    if priority not in ("NORMAL", "HIGH"):
        priority = info["priority"]
        print("Приоритет по умолчанию:", priority)

    message = input("Сообщение: ")

    payload = xor_encrypt(message, key)

    print("Исходный текст:", message)
    print("Зашифрованные данные:", payload)

    data = (
        f"SRP|DATA|{NAME}|{target}|TCP|"
        f"{priority}|1|{payload}"
    )

    client_socket.send(
        (data + "\n").encode("utf-8")
    )


client_socket.close()