import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import re
import subprocess
import threading
import time
import json
import glob
from datetime import datetime

class ConfigManager:
    """Управление файлом настроек"""
    def __init__(self, config_file="openvpn_monitor_config.json"):
        self.config_file = config_file
        self.default_config = {
            "ccd_dir": r"C:\Program Files\OpenVPN\ccd",
            "mask4ccd": "255.255.0.0",
            "status_log": r"C:\Program Files\OpenVPN\config\openvpn-status.log",
            "clients_file": r"C:\OpenVPN_Monitor\clients.json",
            "clients_csv": r"C:\OpenVPN_Monitor\clients_list.csv",
            "auto_update": True,
            "update_interval": 5000,
            "viewer_folder": r"C:\Program Files\OpenVPN\ccd"
        }
        self.config = {}
        self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            except Exception as e:
                print(f"Ошибка загрузки конфигурации: {e}")
                self.config = self.default_config.copy()
        else:
            self.config = self.default_config.copy()
            self.save_config()
    
    def save_config(self):
        try:
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Ошибка сохранения конфигурации: {e}")
            return False
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
        self.save_config()
    
    def update(self, updates):
        self.config.update(updates)
        self.save_config()

class ClientsManager:
    def __init__(self, config_manager):
        self.config = config_manager
        self.clients_file = self.config.get("clients_file", "clients.json")
        self.clients = []
        self.load_clients()
    
    def load_clients(self):
        if os.path.exists(self.clients_file):
            try:
                with open(self.clients_file, 'r', encoding='utf-8') as f:
                    self.clients = json.load(f)
            except Exception as e:
                print(f"Ошибка загрузки клиентов: {e}")
                self.clients = []
        else:
            self.clients = []
            self.save_clients()
    
    def save_clients(self):
        try:
            clients_dir = os.path.dirname(self.clients_file)
            if clients_dir and not os.path.exists(clients_dir):
                os.makedirs(clients_dir)
            with open(self.clients_file, 'w', encoding='utf-8') as f:
                json.dump(self.clients, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Ошибка сохранения клиентов: {e}")
            return False
    
    def add_client(self, client):
        self.clients.append(client)
        self.save_clients()
    
    def update_client(self, index, client):
        if 0 <= index < len(self.clients):
            self.clients[index] = client
            self.save_clients()
    
    def delete_client(self, index):
        if 0 <= index < len(self.clients):
            del self.clients[index]
            self.save_clients()
    
    def get_all_clients(self):
        return self.clients
    
    def export_to_csv(self, csv_file=None):
        if csv_file is None:
            csv_file = self.config.get("clients_csv", "clients_list.csv")
        
        try:
            csv_dir = os.path.dirname(csv_file)
            if csv_dir and not os.path.exists(csv_dir):
                os.makedirs(csv_dir)
            
            with open(csv_file, 'w', encoding='utf-8-sig') as f:
                f.write("Клиент,Ключ,VPN_IP,REAL_IP,комментарий,reserved IP\n")
                for client in self.clients:
                    f.write(f"{client.get('client','')},{client.get('key','')},"
                           f"{client.get('vpn_ip','')},{client.get('real_ip','')},"
                           f"{client.get('comment','')},{client.get('reserved_ip','')}\n")
            return True
        except Exception as e:
            print(f"Ошибка экспорта CSV: {e}")
            return False

class OpenVPNLogParser:
    """Парсер логов OpenVPN"""
    
    @staticmethod
    def parse_status_log(content):
        """Парсинг файла статуса OpenVPN"""
        clients = {}
        
        # Парсим секцию CLIENT LIST для получения информации о клиентах
        client_info = {}  # {client_name: {'real_ip': '', 'bytes': '', 'since': ''}}
        
        # Ищем секцию CLIENT LIST
        client_list_section = re.search(r'OpenVPN CLIENT LIST\n(.*?)\nROUTING TABLE', content, re.DOTALL | re.IGNORECASE)
        if client_list_section:
            lines = client_list_section.group(1).split('\n')
            for line in lines:
                # Пропускаем заголовки и пустые строки
                if not line.strip() or line.startswith('Common Name') or line.startswith('Updated'):
                    continue
                
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 5:
                    client_name = parts[0]
                    real_addr = parts[1]
                    bytes_received = parts[2]
                    bytes_sent = parts[3]
                    connected_since = parts[4]
                    
                    # Извлекаем IP из real_addr (udp6:192.168.0.235:42555 -> 192.168.0.235)
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', real_addr)
                    real_ip = ip_match.group(1) if ip_match else real_addr
                    
                    client_info[client_name] = {
                        'real_ip': real_ip,
                        'real_addr': real_addr,
                        'bytes_received': bytes_received,
                        'bytes_sent': bytes_sent,
                        'connected_since': connected_since
                    }
        
        # Парсим секцию ROUTING TABLE для получения VPN IP
        routing_section = re.search(r'ROUTING TABLE\n(.*?)(?:\nGLOBAL STATS|\n\n|\Z)', content, re.DOTALL | re.IGNORECASE)
        if routing_section:
            lines = routing_section.group(1).split('\n')
            for line in lines:
                if not line.strip() or line.startswith('Virtual Address'):
                    continue
                
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 2:
                    vpn_ip = parts[0]
                    client_name = parts[1]
                    
                    # Если клиент уже есть в client_info, добавляем VPN IP
                    if client_name in client_info:
                        clients[client_name] = {
                            'vpn_ip': vpn_ip,
                            'real_ip': client_info[client_name]['real_ip'],
                            'real_addr': client_info[client_name]['real_addr'],
                            'connected_since': client_info[client_name]['connected_since'],
                            'bytes_received': client_info[client_name]['bytes_received'],
                            'bytes_sent': client_info[client_name]['bytes_sent']
                        }
                    else:
                        # Если клиента нет в CLIENT LIST, создаем запись только с VPN IP
                        clients[client_name] = {
                            'vpn_ip': vpn_ip,
                            'real_ip': '',
                            'connected_since': '',
                            'bytes_received': '',
                            'bytes_sent': ''
                        }
        
        return clients
    
    @staticmethod
    def parse_log_file(log_path):
        """Чтение и парсинг файла лога"""
        if not os.path.exists(log_path):
            return {}
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return OpenVPNLogParser.parse_status_log(content)
        except Exception as e:
            print(f"Ошибка чтения лога: {e}")
            return {}

class OpenVPNStatusMonitor:
    def __init__(self, parent, config_manager, clients_manager):
        self.parent = parent
        self.config = config_manager
        self.clients_manager = clients_manager
        
        self.ccd_dir = tk.StringVar(value=self.config.get("ccd_dir"))
        self.mask4ccd = tk.StringVar(value=self.config.get("mask4ccd"))
        self.status_file = tk.StringVar(value=self.config.get("status_log"))
        
        self.monitoring = False
        self.openvpn_clients = {}  # Словарь с подключенными клиентами
        self.all_clients = []
        
        self.create_widgets()
        self.load_status()
        
        if self.config.get("auto_update", True):
            self.start_auto_update()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Верхняя панель
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        btn_refresh = ttk.Button(top_frame, text="Обновить статус", command=self.load_status)
        btn_refresh.pack(side=tk.LEFT, padx=5)
        
        btn_settings = ttk.Button(top_frame, text="Настройки", command=self.show_settings)
        btn_settings.pack(side=tk.LEFT, padx=5)
        
        btn_export = ttk.Button(top_frame, text="Экспорт CSV", command=self.export_to_csv)
        btn_export.pack(side=tk.LEFT, padx=5)
        
        # Статус
        self.online_count_label = ttk.Label(top_frame, text="Подключено: 0", font=('Arial', 10, 'bold'), foreground='green')
        self.online_count_label.pack(side=tk.RIGHT, padx=10)
        
        self.log_status_label = ttk.Label(top_frame, text="", foreground='blue')
        self.log_status_label.pack(side=tk.RIGHT, padx=10)
        
        self.auto_update_var = tk.BooleanVar(value=self.config.get("auto_update", True))
        ttk.Checkbutton(top_frame, text="Автообновление", variable=self.auto_update_var, 
                       command=self.toggle_auto_update).pack(side=tk.RIGHT, padx=5)
        
        # Панель настроек
        self.settings_frame = ttk.LabelFrame(main_frame, text="Настройки", padding=10)
        
        ttk.Label(self.settings_frame, text="Status Log File:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        log_entry = ttk.Entry(self.settings_frame, textvariable=self.status_file, width=70)
        log_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.settings_frame, text="Обзор", command=self.browse_status_file).grid(row=0, column=2, padx=5)
        ttk.Button(self.settings_frame, text="Проверить файл", command=self.test_log_file).grid(row=0, column=3, padx=5)
        
        ttk.Label(self.settings_frame, text="CCD-dir:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ccd_entry = ttk.Entry(self.settings_frame, textvariable=self.ccd_dir, width=70)
        ccd_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.settings_frame, text="Обзор", command=self.browse_ccd_dir).grid(row=1, column=2, padx=5)
        
        ttk.Label(self.settings_frame, text="Mask4ccd-file:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(self.settings_frame, textvariable=self.mask4ccd, width=20).grid(row=2, column=1, sticky=tk.W, padx=5)
        
        btn_frame = ttk.Frame(self.settings_frame)
        btn_frame.grid(row=3, column=0, columnspan=4, pady=10)
        
        ttk.Button(btn_frame, text="Добавить клиента", command=self.add_client).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Создать CCD файлы", command=self.create_ccd_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Сохранить настройки", command=self.save_current_config).pack(side=tk.LEFT, padx=5)
        
        info_text = f"Файл настроек: {self.config.config_file}\nФайл клиентов: {self.config.get('clients_file')}"
        ttk.Label(self.settings_frame, text=info_text, foreground='gray', justify=tk.LEFT).grid(row=4, column=0, columnspan=4, pady=5, sticky=tk.W)
        
        # Вкладки
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Вкладка подключенных
        self.connected_frame = ttk.Frame(notebook)
        notebook.add(self.connected_frame, text="🟢 Подключенные клиенты")
        self.create_connected_table()
        
        # Вкладка всех клиентов
        self.all_clients_frame = ttk.Frame(notebook)
        notebook.add(self.all_clients_frame, text="📋 Список клиентов")
        self.create_all_clients_table()
        
        # Вкладка лога
        self.log_frame = ttk.Frame(notebook)
        notebook.add(self.log_frame, text="📄 Лог файл")
        self.create_log_tab()
        
        # Вкладка ping
        self.ping_frame = ttk.Frame(notebook)
        notebook.add(self.ping_frame, text="📡 Ping")
        self.create_ping_tab()
    
    def create_connected_table(self):
        table_frame = ttk.Frame(self.connected_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Клиент", "Ключ", "VPN_IP", "REAL_IP", "Получено", "Отправлено", "Подключен с")
        self.connected_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        col_widths = {"Клиент": 120, "Ключ": 100, "VPN_IP": 120, "REAL_IP": 130, "Получено": 100, "Отправлено": 100, "Подключен с": 150}
        for col in columns:
            self.connected_tree.heading(col, text=col)
            self.connected_tree.column(col, width=col_widths.get(col, 120))
        
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.connected_tree.yview)
        self.connected_tree.configure(yscrollcommand=vsb.set)
        
        self.connected_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
    
    def create_all_clients_table(self):
        table_frame = ttk.Frame(self.all_clients_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Клиент", "Ключ", "VPN_IP", "REAL_IP", "комментарий", "reserved IP")
        self.all_clients_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.all_clients_tree.heading(col, text=col)
            self.all_clients_tree.column(col, width=150)
        
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.all_clients_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.all_clients_tree.xview)
        self.all_clients_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.all_clients_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        btn_frame = ttk.Frame(self.all_clients_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="➕ Добавить", command=self.add_client).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="✏️ Редактировать", command=self.edit_selected_client).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🗑️ Удалить", command=self.delete_selected_client).pack(side=tk.LEFT, padx=2)
        
        self.all_clients_tree.bind("<Double-1>", self.on_client_double_click)
        self.all_clients_tree.bind("<Delete>", self.delete_selected_client)
    
    def create_log_tab(self):
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        btn_frame = ttk.Frame(self.log_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Обновить лог", command=self.load_log_content).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Очистить", command=lambda: self.log_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
    
    def create_ping_tab(self):
        ping_frame = ttk.Frame(self.ping_frame)
        ping_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(ping_frame, text="Выберите клиента:").pack(pady=5)
        self.ping_client_combo = ttk.Combobox(ping_frame, width=30)
        self.ping_client_combo.pack(pady=5)
        
        ttk.Label(ping_frame, text="Или введите IP:").pack(pady=5)
        self.ping_entry = ttk.Entry(ping_frame, width=30)
        self.ping_entry.pack(pady=5)
        
        ttk.Button(ping_frame, text="Ping", command=self.ping_vpn).pack(pady=10)
        
        self.ping_result = scrolledtext.ScrolledText(ping_frame, height=15, font=('Consolas', 9))
        self.ping_result.pack(fill=tk.BOTH, expand=True, pady=10)
    
    def test_log_file(self):
        """Тестирование файла лога"""
        log_path = self.status_file.get()
        
        if not os.path.exists(log_path):
            messagebox.showerror("Ошибка", f"Файл не найден:\n{log_path}")
            return
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Парсим
            clients = OpenVPNLogParser.parse_status_log(content)
            
            msg = f"Файл найден! Размер: {os.path.getsize(log_path)} байт\n"
            msg += f"Найдено подключенных клиентов: {len(clients)}\n\n"
            
            if clients:
                msg += f"Найденные клиенты:\n{'-'*50}\n"
                for name, info in clients.items():
                    msg += f"  Клиент: {name}\n"
                    msg += f"    VPN IP: {info.get('vpn_ip', 'Нет')}\n"
                    msg += f"    REAL IP: {info.get('real_ip', 'Нет')}\n"
                    msg += f"    Подключен: {info.get('connected_since', 'Нет')}\n"
                    msg += f"    Трафик: RX={info.get('bytes_received', '0')} TX={info.get('bytes_sent', '0')}\n\n"
            else:
                msg += "\nВНИМАНИЕ: Не удалось найти подключенных клиентов в файле.\n"
                msg += "Убедитесь, что:\n"
                msg += "1. OpenVPN запущен и клиенты подключены\n"
                msg += "2. В конфигурации OpenVPN есть параметр 'status openvpn-status.log'\n"
                msg += "3. Путь к файлу указан верно"
            
            messagebox.showinfo("Результат проверки", msg)
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{str(e)}")
    
    def load_log_content(self):
        """Загрузка содержимого лог-файла"""
        log_path = self.status_file.get()
        
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(1.0, content)
                self.log_status_label.config(text=f"Лог загружен: {os.path.basename(log_path)}", foreground='green')
            except Exception as e:
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(1.0, f"Ошибка чтения: {e}")
                self.log_status_label.config(text=f"Ошибка: {e}", foreground='red')
        else:
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(1.0, f"Файл не найден:\n{log_path}")
            self.log_status_label.config(text="Файл не найден", foreground='red')
    
    def load_status(self):
        """Загрузка статуса подключенных клиентов"""
        log_path = self.status_file.get()
        
        # Парсим лог файл
        self.openvpn_clients = OpenVPNLogParser.parse_log_file(log_path)
        
        # Обновляем статус лога
        if os.path.exists(log_path):
            self.log_status_label.config(text=f"Лог: {os.path.basename(log_path)}", foreground='green')
        else:
            self.log_status_label.config(text="Лог не найден", foreground='red')
        
        # Загружаем всех клиентов
        self.all_clients = self.clients_manager.get_all_clients()
        
        if not self.all_clients:
            self.create_default_clients()
            self.all_clients = self.clients_manager.get_all_clients()
        
        # Обновляем информацию о клиентах из лога
        for client in self.all_clients:
            client_name = client['client']
            if client_name in self.openvpn_clients:
                client['vpn_ip'] = self.openvpn_clients[client_name].get('vpn_ip', client.get('vpn_ip', ''))
                client['real_ip'] = self.openvpn_clients[client_name].get('real_ip', '')
                client['connected_since'] = self.openvpn_clients[client_name].get('connected_since', '')
                client['bytes_received'] = self.openvpn_clients[client_name].get('bytes_received', '')
                client['bytes_sent'] = self.openvpn_clients[client_name].get('bytes_sent', '')
            else:
                client['real_ip'] = ''
                client['connected_since'] = ''
        
        # Обновляем таблицы
        self.update_connected_table()
        self.update_all_clients_table()
        self.update_ping_combo()
        
        # Обновляем счетчик
        self.online_count_label.config(text=f"Подключено: {len(self.openvpn_clients)}")
    
    def update_connected_table(self):
        """Обновление таблицы подключенных клиентов"""
        for item in self.connected_tree.get_children():
            self.connected_tree.delete(item)
        
        for client_name, info in self.openvpn_clients.items():
            # Ищем клиента в списке
            client_info = None
            for client in self.all_clients:
                if client['client'] == client_name:
                    client_info = client
                    break
            
            self.connected_tree.insert("", tk.END, values=(
                client_name,
                client_info.get('key', '') if client_info else '',
                info.get('vpn_ip', ''),
                info.get('real_ip', ''),
                info.get('bytes_received', '0'),
                info.get('bytes_sent', '0'),
                info.get('connected_since', '')
            ))
    
    def update_all_clients_table(self):
        for item in self.all_clients_tree.get_children():
            self.all_clients_tree.delete(item)
        
        for client in self.all_clients:
            tags = ('online',) if client.get('real_ip') else ()
            
            self.all_clients_tree.insert("", tk.END, values=(
                client.get('client', ''),
                client.get('key', ''),
                client.get('vpn_ip', ''),
                client.get('real_ip', ''),
                client.get('comment', ''),
                client.get('reserved_ip', '')
            ), tags=tags)
        
        self.all_clients_tree.tag_configure('online', background='#d4ffd4')
    
    def update_ping_combo(self):
        clients = [c['client'] for c in self.all_clients]
        self.ping_client_combo['values'] = clients
        if clients:
            self.ping_client_combo.set(clients[0])
    
    def create_default_clients(self):
        default_clients = [
            {'client': 'poco', 'key': 'poco', 'vpn_ip': '10.8.10.3', 'real_ip': '', 'comment': 'Клиент POCO', 'reserved_ip': '10.8.10.3'},
            {'client': 'home', 'key': 'home', 'vpn_ip': '10.8.100.2', 'real_ip': '', 'comment': 'Домашний клиент', 'reserved_ip': '10.8.100.2'}
        ]
        
        for client in default_clients:
            self.clients_manager.add_client(client)
    
    def save_current_config(self):
        self.config.update({
            "ccd_dir": self.ccd_dir.get(),
            "mask4ccd": self.mask4ccd.get(),
            "status_log": self.status_file.get(),
            "auto_update": self.auto_update_var.get()
        })
        messagebox.showinfo("Успех", "Настройки сохранены")
    
    def show_settings(self):
        if self.settings_frame.winfo_ismapped():
            self.settings_frame.pack_forget()
        else:
            self.settings_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def browse_ccd_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.ccd_dir.set(dir_path)
    
    def browse_status_file(self):
        file_path = filedialog.askopenfilename(
            title="Выберите файл статуса OpenVPN",
            filetypes=[("Log files", "*.log"), ("Status files", "*.status"), ("All files", "*.*")]
        )
        if file_path:
            self.status_file.set(file_path)
            self.load_status()
    
    def add_client(self):
        dialog = tk.Toplevel(self.parent)
        dialog.title("Добавить клиента")
        dialog.geometry("400x450")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Имя клиента:*").pack(pady=5)
        client_name = ttk.Entry(dialog, width=30)
        client_name.pack(pady=5)
        
        ttk.Label(dialog, text="Ключ:*").pack(pady=5)
        client_key = ttk.Entry(dialog, width=30)
        client_key.pack(pady=5)
        
        ttk.Label(dialog, text="VPN IP:*").pack(pady=5)
        vpn_ip = ttk.Entry(dialog, width=30)
        vpn_ip.pack(pady=5)
        
        ttk.Label(dialog, text="Комментарий:").pack(pady=5)
        comment = ttk.Entry(dialog, width=30)
        comment.pack(pady=5)
        
        ttk.Label(dialog, text="Reserved IP:").pack(pady=5)
        reserved_ip = ttk.Entry(dialog, width=30)
        reserved_ip.pack(pady=5)
        
        def save_client():
            if not client_name.get() or not client_key.get():
                messagebox.showwarning("Предупреждение", "Имя клиента и ключ обязательны!")
                return
            
            new_client = {
                'client': client_name.get(),
                'key': client_key.get(),
                'vpn_ip': vpn_ip.get(),
                'real_ip': '',
                'comment': comment.get(),
                'reserved_ip': reserved_ip.get() or vpn_ip.get()
            }
            self.clients_manager.add_client(new_client)
            self.load_status()
            dialog.destroy()
        
        ttk.Button(dialog, text="Сохранить", command=save_client).pack(pady=20)
    
    def edit_selected_client(self):
        selection = self.all_clients_tree.selection()
        if selection:
            self.on_client_double_click(None)
    
    def delete_selected_client(self, event=None):
        selection = self.all_clients_tree.selection()
        if selection and messagebox.askyesno("Подтверждение", "Удалить выбранного клиента?"):
            item = self.all_clients_tree.item(selection[0])
            values = item['values']
            
            clients = self.clients_manager.get_all_clients()
            for i, client in enumerate(clients):
                if client['client'] == values[0]:
                    self.clients_manager.delete_client(i)
                    break
            
            self.load_status()
    
    def on_client_double_click(self, event):
        selection = self.all_clients_tree.selection()
        if not selection:
            return
        
        item = self.all_clients_tree.item(selection[0])
        values = item['values']
        
        dialog = tk.Toplevel(self.parent)
        dialog.title(f"Редактирование - {values[0]}")
        dialog.geometry("400x450")
        
        ttk.Label(dialog, text="Клиент:*").pack(pady=5)
        client_entry = ttk.Entry(dialog, width=30)
        client_entry.insert(0, values[0])
        client_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Ключ:*").pack(pady=5)
        key_entry = ttk.Entry(dialog, width=30)
        key_entry.insert(0, values[1])
        key_entry.pack(pady=5)
        
        ttk.Label(dialog, text="VPN IP:").pack(pady=5)
        ip_entry = ttk.Entry(dialog, width=30)
        ip_entry.insert(0, values[2] if values[2] else "")
        ip_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Комментарий:").pack(pady=5)
        comment_entry = ttk.Entry(dialog, width=30)
        comment_entry.insert(0, values[4] if values[4] else "")
        comment_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Reserved IP:").pack(pady=5)
        reserved_entry = ttk.Entry(dialog, width=30)
        reserved_entry.insert(0, values[5] if values[5] else "")
        reserved_entry.pack(pady=5)
        
        def update_client():
            clients = self.clients_manager.get_all_clients()
            for i, client in enumerate(clients):
                if client['client'] == values[0]:
                    updated_client = {
                        'client': client_entry.get(),
                        'key': key_entry.get(),
                        'vpn_ip': ip_entry.get(),
                        'real_ip': client.get('real_ip', ''),
                        'comment': comment_entry.get(),
                        'reserved_ip': reserved_entry.get()
                    }
                    self.clients_manager.update_client(i, updated_client)
                    break
            
            self.load_status()
            dialog.destroy()
        
        ttk.Button(dialog, text="Обновить", command=update_client).pack(pady=10)
        ttk.Button(dialog, text="Отмена", command=dialog.destroy).pack(pady=5)
    
    def create_ccd_file(self):
        ccd_dir = self.ccd_dir.get()
        if not os.path.exists(ccd_dir):
            os.makedirs(ccd_dir)
        
        created = 0
        for client in self.clients_manager.get_all_clients():
            if client.get('vpn_ip') and client['vpn_ip']:
                ccd_path = os.path.join(ccd_dir, client['client'])
                try:
                    with open(ccd_path, 'w') as f:
                        f.write(f'ifconfig-push {client["vpn_ip"]} {self.mask4ccd.get()}\n')
                    created += 1
                except Exception as e:
                    print(f"Ошибка: {e}")
        
        messagebox.showinfo("Успех", f"Создано CCD файлов: {created}\nПапка: {ccd_dir}")
    
    def export_to_csv(self):
        csv_file = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="clients_list.csv",
            filetypes=[("CSV files", "*.csv")]
        )
        
        if csv_file and self.clients_manager.export_to_csv(csv_file):
            messagebox.showinfo("Успех", f"Экспорт выполнен:\n{csv_file}")
    
    def ping_vpn(self):
        ip = self.ping_entry.get().strip()
        selected_client = self.ping_client_combo.get()
        
        if not ip and selected_client:
            for client in self.all_clients:
                if client['client'] == selected_client:
                    ip = client.get('vpn_ip', '')
                    break
        
        if not ip:
            messagebox.showwarning("Предупреждение", "Введите IP или выберите клиента")
            return
        
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Pinging {ip}...\n\n")
        
        def ping_thread():
            try:
                result = subprocess.run(['ping', '-n', '4', ip], capture_output=True, text=True, encoding='cp866')
                self.parent.after(0, lambda: self.ping_result.insert(tk.END, result.stdout))
                
                if result.returncode == 0:
                    self.parent.after(0, lambda: self.ping_result.insert(tk.END, "\n✅ Успешный ping!"))
                else:
                    self.parent.after(0, lambda: self.ping_result.insert(tk.END, "\n❌ Хост недоступен!"))
            except Exception as e:
                self.parent.after(0, lambda: self.ping_result.insert(tk.END, f"\nОшибка: {e}"))
        
        threading.Thread(target=ping_thread, daemon=True).start()
    
    def toggle_auto_update(self):
        if self.auto_update_var.get():
            self.start_auto_update()
        else:
            self.stop_auto_update()
        self.config.set("auto_update", self.auto_update_var.get())
    
    def start_auto_update(self):
        self.monitoring = True
        self.auto_update()
    
    def stop_auto_update(self):
        self.monitoring = False
    
    def auto_update(self):
        if self.monitoring and self.auto_update_var.get():
            self.load_status()
            self.parent.after(self.config.get("update_interval", 5000), self.auto_update)

class TextFileViewer:
    def __init__(self, parent, config_manager):
        self.parent = parent
        self.config = config_manager
        self.folder_path = self.config.get("viewer_folder", r"C:\Program Files\OpenVPN\config")
        self.current_file = None
        self.create_widgets()
        self.load_file_list()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(top_frame, text="Папка:").pack(side=tk.LEFT, padx=5)
        self.folder_var = tk.StringVar(value=self.folder_path)
        folder_entry = ttk.Entry(top_frame, textvariable=self.folder_var, width=50)
        folder_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Обзор", command=self.browse_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Обновить", command=self.load_file_list).pack(side=tk.LEFT, padx=5)
        
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        files_frame = ttk.LabelFrame(content_frame, text="Файлы", width=250)
        files_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        self.files_listbox = tk.Listbox(files_frame, font=('Consolas', 9))
        self.files_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.files_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        view_frame = ttk.LabelFrame(content_frame, text="Содержимое", padding=5)
        view_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.text_area = scrolledtext.ScrolledText(view_frame, wrap=tk.WORD, font=('Consolas', 10))
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=5)
        
        self.file_info_label = ttk.Label(info_frame, text="Выберите файл")
        self.file_info_label.pack(side=tk.LEFT)
        
        ttk.Button(info_frame, text="Сохранить", command=self.save_file).pack(side=tk.RIGHT, padx=5)
    
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_var.set(folder)
            self.config.set("viewer_folder", folder)
            self.load_file_list()
    
    def load_file_list(self):
        self.files_listbox.delete(0, tk.END)
        folder = self.folder_var.get()
        
        if os.path.exists(folder):
            for file_path in glob.glob(os.path.join(folder, "*")):
                if os.path.isfile(file_path):
                    self.files_listbox.insert(tk.END, os.path.basename(file_path))
    
    def on_file_select(self, event):
        selection = self.files_listbox.curselection()
        if selection:
            filename = self.files_listbox.get(selection[0])
            file_path = os.path.join(self.folder_var.get(), filename)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.insert(1.0, f.read())
                    self.current_file = file_path
                    self.file_info_label.config(text=f"Файл: {filename}")
            except Exception as e:
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(1.0, f"Ошибка: {e}")
    
    def save_file(self):
        if self.current_file:
            try:
                with open(self.current_file, 'w', encoding='utf-8') as f:
                    f.write(self.text_area.get(1.0, tk.END).rstrip())
                messagebox.showinfo("Успех", "Файл сохранен")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

class CombinedApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenVPN Status Monitor PRO PLUS MAX")
        self.root.geometry("1300x800")
        
        self.config_manager = ConfigManager("openvpn_monitor_config.json")
        self.clients_manager = ClientsManager(self.config_manager)
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text="🔐 OpenVPN Monitor")
        self.monitor = OpenVPNStatusMonitor(self.monitor_frame, self.config_manager, self.clients_manager)
        
        self.editor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.editor_frame, text="📁 Файлы конфигурации")
        self.file_viewer = TextFileViewer(self.editor_frame, self.config_manager)
        
        root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def on_closing(self):
        if hasattr(self.monitor, 'stop_auto_update'):
            self.monitor.stop_auto_update()
        self.config_manager.save_config()
        self.clients_manager.save_clients()
        self.root.destroy()

def main():
    root = tk.Tk()
    app = CombinedApplication(root)
    root.mainloop()

if __name__ == "__main__":
    main()
