import asyncio
import argparse
import struct
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def parse_proxy_file(file_path):
    proxies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    auth, address = line.split('@')
                    username, password = auth.split(':')
                    host, port = address.split(':')
                    proxies.append((host, int(port), username, password))
                except ValueError as e:
                    logging.error(f"Ошибка парсинга строки '{line}': {e}")
        return proxies
    except FileNotFoundError:
        logging.error(f"Файл {file_path} не найден")
        return []
    except Exception as e:
        logging.error(f"Ошибка чтения файла {file_path}: {e}")
        return []


async def socks5_server_handshake(reader, writer):
    data = await reader.read(2)
    if len(data) < 2 or data[0] != 5:
        writer.close()
        return False, None, None
    nmethods = data[1]
    methods = await reader.read(nmethods)
    if 0 not in methods:
        writer.write(b'\x05\xff')
        await writer.drain()
        writer.close()
        return False, None, None
    writer.write(b'\x05\x00')
    await writer.drain()
    data = await reader.read(4)
    if len(data) < 4 or data[0] != 5 or data[1] != 1:
        writer.close()
        return False, None, None
    atyp = data[3]
    if atyp == 1:
        addr = await reader.read(4)
        host = socket.inet_ntoa(addr)
    elif atyp == 3:
        addr_len = (await reader.read(1))[0]
        addr = await reader.read(addr_len)
        host = addr.decode()
    else:
        writer.close()
        return False, None, None
    port = struct.unpack('>H', await reader.read(2))[0]
    writer.write(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('>H', 0))
    await writer.drain()
    return True, host, port


async def socks5_client_connect(reader, writer, remote_host, remote_port, username, password, target_host, target_port):
    try:
        writer.write(b'\x05\x01\x02')
        await writer.drain()
        data = await reader.read(2)
        if len(data) < 2 or data[0] != 5 or data[1] != 2:
            return False
        username = username.encode()
        password = password.encode()
        writer.write(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
        await writer.drain()
        data = await reader.read(2)
        if len(data) < 2 or data[0] != 1 or data[1] != 0:
            return False
        writer.write(b'\x05\x01\x00')
        if ':' in target_host:
            return False
        try:
            ip = socket.inet_aton(target_host)
            writer.write(b'\x01' + ip)
        except socket.error:
            target_bytes = target_host.encode()
            writer.write(b'\x03' + bytes([len(target_bytes)]) + target_bytes)
        writer.write(struct.pack('>H', target_port))
        await writer.drain()
        data = await reader.read(4)
        if len(data) < 4 or data[0] != 5 or data[1] != 0:
            return False
        atyp = data[3]
        if atyp == 1:
            await reader.read(4)
        elif atyp == 3:
            addr_len = (await reader.read(1))[0]
            await reader.read(addr_len)
        else:
            return False
        await reader.read(2)
        return True
    except Exception:
        return False


async def handle_client(reader, writer, remote_proxy):
    try:
        success, target_host, target_port = await socks5_server_handshake(reader, writer)
        if not success:
            return
        remote_host, remote_port, username, password = remote_proxy
        try:
            client_reader, client_writer = await asyncio.wait_for(
                asyncio.open_connection(remote_host, remote_port),
                timeout=10
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            logging.error(f"Удалённый прокси {remote_host}:{remote_port} не отвечает: {e}")
            writer.close()
            return
        success = await socks5_client_connect(
            client_reader, client_writer, remote_host, remote_port,
            username, password, target_host, target_port
        )
        if not success:
            logging.error(f"Не удалось подключиться к удалённому прокси {remote_host}:{remote_port}")
            writer.close()
            client_writer.close()
            return

        async def forward(src_reader, dst_writer):
            try:
                while True:
                    data = await src_reader.read(1024)
                    if not data:
                        break
                    dst_writer.write(data)
                    await dst_writer.drain()
            except Exception:
                pass
            finally:
                dst_writer.close()

        await asyncio.gather(
            forward(reader, client_writer),
            forward(client_reader, writer)
        )
    except Exception as e:
        logging.error(f"Ошибка в обработке клиента: {e}")
    finally:
        writer.close()


async def start_proxy_server(local_port, remote_proxy):
    try:
        server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, remote_proxy),
            '127.0.0.1',
            local_port
        )
        logging.info(f"SOCKS5-прокси запущен на 127.0.0.1:{local_port} -> {remote_proxy[0]}:{remote_proxy[1]}")
        async with server:
            await server.serve_forever()
    except Exception as e:
        logging.error(f"Ошибка запуска сервера на порту {local_port}: {e}")


async def main(proxy_file):
    proxy_list = parse_proxy_file(proxy_file)
    if not proxy_list:
        logging.error("Не удалось загрузить прокси. Завершение работы.")
        return
    tasks = []
    start_port = 1000
    for i, proxy in enumerate(proxy_list):
        local_port = start_port + i
        task = asyncio.create_task(start_proxy_server(local_port, proxy))
        tasks.append(task)
    await asyncio.gather(*tasks)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Запуск локальных SOCKS5-прокси с перенаправлением на удалённые прокси.')
    parser.add_argument('proxy_file', help='Путь к файлу с прокси в формате username:password@host:port')
    args = parser.parse_args()
    asyncio.run(main(args.proxy_file))
