import socket
import json
import threading
import sys

from routing import build_graph, shortest_path, print_routing_table


HOST = "127.0.0.1"


def load_json(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


if len(sys.argv) != 2:
    print("Запуск: py router.py ИмяМаршрутизатора")
    print("Например: py router.py Router1")
    sys.exit()

MY_NAME = sys.argv[1]

network = load_json("network.json")
clients = load_json("clients.json")

if MY_NAME not in network["routers"]:
    print("Неизвестный маршрутизатор:", MY_NAME)
    sys.exit()

TCP_PORT = network["routers"][MY_NAME]["tcp_port"]
UDP_PORT = network["routers"][MY_NAME]["udp_port"]

# клиенты, подключённые именно к этому маршрутизатору
connected_clients = {}

udp_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)


def send_to_client(target, packet):
    if target not in connected_clients:
        print(f"[{MY_NAME}] Клиент {target} не подключён.")
        return

    client = connected_clients[target]

    if client["protocol"] == "TCP":
        client["conn"].sendall(
            (packet + "\n").encode("utf-8")
        )
    else:
        udp_socket.sendto(
            packet.encode("utf-8"),
            client["address"]
        )


def send_to_router(next_router, packet):
    port = network["routers"][next_router]["tcp_port"]

    try:
        link_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        link_socket.connect((HOST, port))
        link_socket.sendall(
            (packet + "\n").encode("utf-8")
        )
        link_socket.close()
    except OSError:
        print(f"[{MY_NAME}] Не удалось передать пакет: {next_router} недоступен.")


def get_link_type(first, second):
    for link in network["links"]:
        if (
            (link["from"] == first and link["to"] == second)
            or (link["from"] == second and link["to"] == first)
        ):
            return link["type"]

    return "?"


def process_message(packet):
    global network

    parts = packet.split("|", 7)

    if len(parts) != 8:
        print(f"[{MY_NAME}] Неверный формат пакета.")
        return

    source = parts[2]
    target = parts[3]
    protocol = parts[4]
    priority = parts[5]
    encrypted = parts[6]
    payload = parts[7]

    # топология перечитывается при каждом пакете,
    # чтобы изменения network.json действовали сразу
    network = load_json("network.json")

    print()
    print(f"[{MY_NAME}] ПОЛУЧЕНО СООБЩЕНИЕ")

    if target not in clients:
        print(f"[{MY_NAME}] Получатель {target} не найден.")
        return

    sender_info = clients.get(source)
    target_info = clients[target]
    target_router = target_info["router"]

    print("Отправитель:", source)
    print("Получатель:", target)

    if sender_info:
        print("Сеть отправителя:", sender_info["network"])
    print("Сеть получателя:", target_info["network"])
    print("Протокол отправителя:", protocol)
    print("Протокол получателя:", target_info["protocol"])
    print("Приоритет:", priority)
    print("Зашифровано:", encrypted)
    print("Payload:", payload)

    if priority == "HIGH":
        print(f"[{MY_NAME}] Приоритетное сообщение.")

    if target_router == MY_NAME:
        print(f"[{MY_NAME}] Получатель подключён к этому маршрутизатору.")

        if protocol != target_info["protocol"]:
            print(f"[{MY_NAME}] Выполняется преобразование протокола.")

        send_to_client(target, packet)
        return

    graph = build_graph(network)

    path, cost = shortest_path(graph, MY_NAME, target_router)

    if cost == float("inf"):
        print(f"[{MY_NAME}] Маршрут до {target_router} не найден.")
        return

    next_router = path[1]

    print()
    print("Источник:", MY_NAME)
    print("Назначение:", target_router)
    print()
    print("Кратчайший путь:")
    print(" -> ".join(path))
    print()
    print("Стоимость:")
    print(cost)
    print()
    print("Следующий маршрутизатор:", next_router)
    print("Тип канала:", get_link_type(MY_NAME, next_router))

    send_to_router(next_router, packet)


def check_registration(name, protocol):
    if name not in clients:
        return False

    if clients[name]["router"] != MY_NAME:
        return False

    if clients[name]["protocol"] != protocol:
        return False

    return True


def handle_tcp_client(conn, address):
    name = None

    try:
        reader = conn.makefile("r", encoding="utf-8")

        for line in reader:
            line = line.strip()

            if not line:
                continue

            if line.startswith("SRP|REGISTER|"):
                name = line.split("|")[2]

                if check_registration(name, "TCP"):
                    connected_clients[name] = {
                        "protocol": "TCP",
                        "conn": conn
                    }

                    print()
                    print(f"[{MY_NAME}] TCP-клиент подключён:", name)
                    print("Сеть:", clients[name]["network"])
                    print("Приоритет:", clients[name]["priority"])

                    conn.sendall(
                        "SRP|OK|Регистрация выполнена.\n".encode("utf-8")
                    )
                else:
                    conn.sendall(
                        "SRP|ERROR|Регистрация отклонена.\n".encode("utf-8")
                    )
                    name = None

            elif line.startswith("SRP|DATA|"):
                process_message(line)

    except OSError:
        pass

    finally:
        if name in connected_clients:
            if connected_clients[name].get("conn") is conn:
                del connected_clients[name]
                print(f"[{MY_NAME}] Клиент {name} отключён.")

        conn.close()


def tcp_server():
    tcp_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    tcp_socket.bind((HOST, TCP_PORT))
    tcp_socket.listen()

    print(f"[{MY_NAME}] TCP ожидает подключения: {HOST}:{TCP_PORT}")

    while True:
        conn, address = tcp_socket.accept()

        thread = threading.Thread(
            target=handle_tcp_client,
            args=(conn, address)
        )

        thread.start()


def udp_server():
    udp_socket.bind((HOST, UDP_PORT))

    print(f"[{MY_NAME}] UDP ожидает сообщения: {HOST}:{UDP_PORT}")

    while True:
        try:
            data, address = udp_socket.recvfrom(4096)
        except ConnectionResetError:
            # Windows: клиент закрыл UDP-сокет
            continue

        message = data.decode("utf-8")

        if message.startswith("SRP|REGISTER|"):
            name = message.split("|")[2]

            if check_registration(name, "UDP"):
                connected_clients[name] = {
                    "protocol": "UDP",
                    "address": address
                }

                print()
                print(f"[{MY_NAME}] UDP-клиент подключён:", name)
                print("Сеть:", clients[name]["network"])
                print("Приоритет:", clients[name]["priority"])

                udp_socket.sendto(
                    "SRP|OK|Регистрация выполнена.".encode("utf-8"),
                    address
                )
            else:
                udp_socket.sendto(
                    "SRP|ERROR|Регистрация отклонена.".encode("utf-8"),
                    address
                )

        elif message.startswith("SRP|DATA|"):
            process_message(message)


print_routing_table(
    build_graph(network),
    MY_NAME
)

tcp_thread = threading.Thread(
    target=tcp_server
)

udp_thread = threading.Thread(
    target=udp_server
)

tcp_thread.start()
udp_thread.start()