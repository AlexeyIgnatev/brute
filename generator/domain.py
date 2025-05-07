import sys
from pathlib import Path
import os


def generate_domain_usernames(domain: str, input_path: str):
    input_file = Path(input_path)
    if not input_file.is_file():
        print(f"[Ошибка] Файл не найден: {input_path}")
        sys.exit(1)

    with input_file.open("r", encoding="utf-8") as f:
        usernames = [line.strip() for line in f if line.strip()]

    file_name = domain.replace(".", "_") + ".txt"
    folder = 'domains'

    if not os.path.exists(folder):
        os.mkdir(folder)

    file_name = os.path.join(folder, file_name)

    with open(file_name, "w", encoding="utf-8") as f:
        for username in usernames:
            f.write(f"{domain}\\{username}\n")

    print(f"[✓] Файл успешно создан: {file_name} ({len(usernames)} строк)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Использование: python domain.py <домен> <файл_с_логинами>")
        sys.exit(1)

    generate_domain_usernames(sys.argv[1], sys.argv[2])
