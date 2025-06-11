import os
import re
from deep_translator import GoogleTranslator

TACTIC_PATHS = {
    "TA0043 - Разведка": "documentation/modules/auxiliary/scanner/http",
    "TA0002 - Выполнение": "documentation/modules/exploit/multi/http",
    "TA0003 - Закрепление": "documentation/modules/post/multi/manage",
    "TA0004 - Повышение привилегий": "documentation/modules/exploit/multi/local",
    "TA0006 - Получение учетных данных": "documentation/modules/post/multi/gather",
    "TA0040 - Деструктивное воздействие": "documentation/modules/post/multi/gather",
}

def choose_option(options, prompt, default):
    """Позволяет пользователю выбрать опцию из списка."""
    print(f"\n=== {prompt} ===")
    for i, option in enumerate(options, start=1):
        print(f"[{i}] {option}")
    try:
        choice = int(input("Введите номер вашего выбора: ").strip()) - 1
        return options[choice] if 0 <= choice < len(options) else default
    except ValueError:
        print(f"Некорректный ввод. Установлено значение по умолчанию: {default}.")
        return default

def choose_tactics():
    """Позволяет пользователю выбрать тактики из MITRE ATT&CK."""
    selected_tactics = []
    print("\n=== Выберите тактику из MITRE ATT&CK ===")
    while True:
        for i, (key, path) in enumerate(TACTIC_PATHS.items(), start=1):
            print(f"[{i}] {key}{' (уже выбрано)' if key in selected_tactics else ''}")
        print("[7] Завершить выбор тактик")

        choice = input("Введите номер вашего выбора: ").strip()
        if choice == "7":
            break

        try:
            tactic = list(TACTIC_PATHS.keys())[int(choice) - 1] if choice.isdigit() else choice
            if tactic in TACTIC_PATHS and tactic not in selected_tactics:
                selected_tactics.append(tactic)
            else:
                print("Некорректный выбор или тактика уже выбрана.")
        except (ValueError, IndexError):
            print("Некорректный ввод.")
    return selected_tactics

def process_tactic(tactic, software_list):
    """Обрабатывает выбранную тактику."""
    base_path = TACTIC_PATHS.get(tactic)
    if not base_path or not os.path.exists(base_path):
        print(f"# Тактика {tactic} не поддерживается или папка не найдена.")
        return

    print(f"\n=== Обработка тактики: {tactic} ===")
    modules = [m for m in os.listdir(base_path) if m.endswith(".md") and any(soft.lower() in m.lower() for soft in software_list)]
    if not modules:
        print("  Нет модулей, соответствующих введённому программному обеспечению.")
        return

    module_cve_map = {}
    for i, module in enumerate(modules, start=1):
        relative_rb_path = generate_ruby_path(os.path.join(base_path, module).replace("\\", "/"))
        cve = extract_cve_from_ruby(relative_rb_path)
        if cve:
            cve = re.sub(r"(\d{4}-\d{4,})(.*)", r"\1", cve)
        module_cve_map[module] = cve
        cve_output = f"CVE: {cve}" if cve else "Нет данных о CVE"
        print("[{0:2}] {1:<50} {2}".format(i, module, cve_output))

    print(f"[{len(modules) + 1}] Нужного модуля нет - будет использован модуль handler для работы с разработанным эксплойтом.")

    choice = input("Введите номер вашего выбора: ").strip()
    if choice == str(len(modules) + 1):
        print("Самописная уязвимость выбрана. Дальнейшие действия не выполняются.")
        return

    if not choice.isdigit() or int(choice) - 1 not in range(len(modules)):
        print("Некорректный выбор.")
        return

    selected_module = modules[int(choice) - 1]
    module_path = os.path.join(base_path, selected_module).replace("\\", "/")
    relative_rb_path = generate_ruby_path(module_path)
    print(relative_rb_path)

    translate_and_save_md(module_path, selected_module)
    extract_ruby_data(relative_rb_path)

def generate_ruby_path(module_path):
    """Генерирует путь Ruby файла из пути Markdown."""
    relative_module_path = module_path.replace("documentation/", "").lstrip("/")
    parts = relative_module_path.split("/")

    if len(parts) > 2 and parts[0] == "modules" and parts[1] == "exploit":
        parts[1] += "s"

    return "/".join(parts).replace(".md", ".rb")

def translate_and_save_md(module_path, selected_module):
    """Переводит содержимое MD файла и сохраняет его."""
    try:
        with open(module_path, "r", encoding="utf-8") as md_file:
            md_content = md_file.read()
        blocks = [md_content[i:i+4000] for i in range(0, len(md_content), 4000)]
        translated_blocks = [GoogleTranslator(source="en", target="ru").translate(block) for block in blocks]
        translated_md_content = "".join(translated_blocks)

        # Создаем папку Scenario, если она не существует
        scenario_dir = "Scenario"
        os.makedirs(scenario_dir, exist_ok=True)

        md_output_path = os.path.join(scenario_dir, f"{selected_module}".replace(".md", "_ru.md"))
        with open(md_output_path, "w", encoding="utf-8") as output_file:
            output_file.write(translated_md_content)
        print(f"MD файл переведён и сохранён в: {md_output_path}")
    except Exception as e:
        print(f"Ошибка при обработке MD файла: {e}")

def extract_cve_from_ruby(rb_path):
    """Извлекает CVE из Ruby файла."""
    try:
        with open(rb_path, "r", encoding="utf-8") as ruby_file:
            for line in ruby_file:
                if "'CVE'" in line:
                    parts = line.split("'CVE',", 1)
                    if len(parts) > 1:
                        return parts[1].strip(" []',")
    except FileNotFoundError:
        return None

def extract_ruby_data(new_path):
    """Извлекает данные из Ruby файла."""
    try:
        with open(new_path, "r", encoding="utf-8") as ruby_file:
            ruby_content = ruby_file.read()
    except FileNotFoundError:
        print(f"Файл {new_path} не найден.")
        return

    description, cve_references, options = parse_ruby_content(ruby_content)
    print(f"Описание: {description.strip()}")
    print(f"CVE: {', '.join(cve_references)}")
    print(f"Опции: {options}")

def parse_ruby_content(content):
    """Парсит содержимое Ruby файла."""
    description = ""
    cve_references = []
    options = {}

    desc_start = content.find("Description")
    if desc_start != -1:
        brace_open = content.find("{", desc_start)
        brace_close = content.find("}", brace_open)
        if brace_open != -1 and brace_close != -1:
            description = GoogleTranslator(source="en", target="ru").translate(
                content[brace_open + 1:brace_close].strip()
            )

    for line in content.splitlines():
        line = line.strip()
        if "'CVE'" in line:
            cve_references.append(line.split("'CVE',", 1)[1].strip(" []',"))

    options_start = content.find("register_options")
    if options_start != -1:
        options_block = content[options_start:]
        bracket_count = 0
        option_lines = []
        for line in options_block.splitlines():
            line = line.strip()
            if "[" in line:
                bracket_count += 1
            if "]" in line:
                bracket_count -= 1
                if bracket_count == 0:
                    break
            if bracket_count > 0 and ".new(" in line:
                option_lines.append(line)

        for line in option_lines:
            match = re.search(r"\w+\.new\(\s*'([^']+)'\s*,\s*\[\s*[^,]+,\s*'([^']+)'", line)
            if match:
                option_name, option_desc = match.groups()
                options[option_name] = GoogleTranslator(source="en", target="ru").translate(option_desc)

    return description, cve_references, options

if __name__ == "__main__":
    os_type = choose_option(["Windows", "Linux", "Multi"], "Выберите операционную систему", "Multi")
    segment = choose_option(["DMZ", "Data Center", "Office Users"], "Выберите сегмент сети", "DMZ")
    software = input("Введите название программного обеспечения (для лучшего поиска все вариации названий через запятую): ").strip()
    software_list = [s.strip() for s in software.split(",")]
    selected_tactics = choose_tactics()

    for tactic in selected_tactics:
        process_tactic(tactic, software_list)
