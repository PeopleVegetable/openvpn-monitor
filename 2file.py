import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import re
import subprocess
import threading
import time
from datetime import datetime
import glob

class OpenVPNStatusMonitor:
    def __init__(self, parent):
        self.parent = parent
        
        # Переменные для настроек
        self.ccd_dir = tk.StringVar(value=r"C:\Program Files\OpenVPN\ccd")
        self.mask4ccd = tk.StringVar(value="255.255.0.0")
        self.log_file = tk.StringVar(value=r"C:\Program Files\OpenVPN\log\openvpn-status.log")
        self.status_file = tk.StringVar(value=r"C:\Program Files\OpenVPN\log\openvpn-status.log")
        
        self.monitoring = False
        self.clients_data = []
        self.online_clients = []
        
        self.create_widgets()
        self.load_status()
        
        # Запуск автоматического обновления
        self.start_auto_update()
    
    def create_widgets(self):
        # Создание вкладок для этого фрейма
        self.notebook = ttk.Notebook(self.parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка Status Monitor
        self.status_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.status_frame, text="Update")
        
        # Вкладка RDP
        self.rdp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rdp_frame, text="RDP")
        
        # Вкладка RDP real_IP
        self.rdp_real_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rdp_real_frame, text="RDP real_IP")
        
        # Вкладка Ping-vpn
        self.ping_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ping_frame, text="Ping-vpn")
        
        # Создание интерфейса для вкладки Update
        self.create_update_tab()
        
        # Создание интерфейса для других вкладок
        self.create_rdp_tabs()
    
    def create_update_tab(self):
        # Верхняя панель с кнопками
        top_frame = ttk.Frame(self.status_frame)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Кнопки секций
        btn_connected = ttk.Button(top_frame, text="Подключены", command=self.show_connected_clients)
        btn_connected.pack(side=tk.LEFT, padx=5)
        
        btn_clients = ttk.Button(top_frame, text="Список клиентов", command=self.show_clients_list)
        btn_clients.pack(side=tk.LEFT, padx=5)
        
        btn_settings = ttk.Button(top_frame, text="Настройки", command=self.show_settings)
        btn_settings.pack(side=tk.LEFT, padx=5)
        
        # Панель настроек (скрыта по умолчанию)
        self.settings_frame = ttk.LabelFrame(self.status_frame, text="Настройки", padding=10)
        
        # CCD-dir
        ttk.Label(self.settings_frame, text="CCD-dir:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ccd_entry = ttk.Entry(self.settings_frame, textvariable=self.ccd_dir, width=50)
        ccd_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.settings_frame, text="Обзор", command=self.browse_ccd_dir).grid(row=0, column=2, padx=5)
        
        # Status Log File
        ttk.Label(self.settings_frame, text="Status Log File:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        log_entry = ttk.Entry(self.settings_frame, textvariable=self.status_file, width=50)
        log_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(self.settings_frame, text="Обзор", command=self.browse_status_file).grid(row=1, column=2, padx=5)
        
        # Mask4ccd-file
        ttk.Label(self.settings_frame, text="Mask4ccd-file:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(self.settings_frame, textvariable=self.mask4ccd, width=20).grid(row=2, column=1, sticky=tk.W, padx=5)
        
        # Кнопки действий
        action_frame = ttk.Frame(self.settings_frame)
        action_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        ttk.Button(action_frame, text="Добавить", command=self.add_client).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Сохранить список", command=self.save_clients_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Создать CCD-файл", command=self.create_ccd_file).pack(side=tk.LEFT, padx=5)
        
        # Таблица клиентов
        self.create_clients_table()
        
        # Нижняя панель со статусом
        status_bar = ttk.Frame(self.status_frame)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=5)
        
        self.online_label = ttk.Label(status_bar, text="Clients Online: 0", font=('Arial', 10, 'bold'))
        self.online_label.pack(side=tk.LEFT)
        
        self.update_btn = ttk.Button(status_bar, text="Обновить", command=self.load_status)
        self.update_btn.pack(side=tk.RIGHT, padx=5)
        
        self.auto_update_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(status_bar, text="Автообновление", variable=self.auto_update_var, command=self.toggle_auto_update).pack(side=tk.RIGHT, padx=5)
        
        # Кнопка для тестовых данных
        ttk.Button(status_bar, text="Тестовые данные", command=self.load_demo_data).pack(side=tk.RIGHT, padx=5)
    
    def create_clients_table(self):
        # Создание фрейма для таблицы
        table_frame = ttk.Frame(self.status_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Создание Treeview
        columns = ("Клиент", "Ключ", "VPN_IP", "REAL_IP", "комментарий", "reserved IP")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        # Настройка заголовков
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # Добавление скроллбаров
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Размещение
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Привязка двойного клика
        self.tree.bind("<Double-1>", self.on_client_double_click)
    
    def create_rdp_tabs(self):
        # Вкладка RDP
        rdp_text = scrolledtext.ScrolledText(self.rdp_frame, wrap=tk.WORD, font=('Consolas', 10))
        rdp_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        rdp_text.insert(tk.END, "Инструменты RDP будут здесь\n")
        
        # Вкладка RDP real_IP
        rdp_real_text = scrolledtext.ScrolledText(self.rdp_real_frame, wrap=tk.WORD, font=('Consolas', 10))
        rdp_real_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        rdp_real_text.insert(tk.END, "RDP с реальными IP адресами\n")
        
        # Вкладка Ping-vpn
        ping_frame_inner = ttk.Frame(self.ping_frame)
        ping_frame_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(ping_frame_inner, text="VPN IP адрес:").pack(pady=5)
        self.ping_entry = ttk.Entry(ping_frame_inner, width=30)
        self.ping_entry.pack(pady=5)
        
        ttk.Button(ping_frame_inner, text="Ping", command=self.ping_vpn).pack(pady=5)
        
        self.ping_result = scrolledtext.ScrolledText(ping_frame_inner, height=15, font=('Consolas', 9))
        self.ping_result.pack(fill=tk.BOTH, expand=True, pady=10)
    
    def load_status(self):
        """Загрузка статуса из лог-файла OpenVPN"""
        log_path = self.status_file.get()
        
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    self.parse_status_log(content)
                messagebox.showinfo("Успех", f"Данные загружены из {log_path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка чтения лога:\n{str(e)}")
                self.load_demo_data()
        else:
            messagebox.showwarning("Предупреждение", f"Файл статуса не найден:\n{log_path}\n\nЗагружены тестовые данные.")
            self.load_demo_data()
    
    def parse_status_log(self, content):
        """Парсинг лог-файла OpenVPN"""
        self.clients_data = []
        self.online_clients = []
        
        # Поиск секции с клиентами (формат OpenVPN 2.x)
        # Ищем строки вида: "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"
        clients_section = re.search(r'Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since[^\n]*\n(.*?)(?:\n\n|\n$)', content, re.DOTALL | re.MULTILINE)
        
        if not clients_section:
            # Альтернативный формат
            clients_section = re.search(r'CLIENT_LIST\t(.*?)(?:\n\n|\n$)', content, re.DOTALL)
        
        if clients_section:
            lines = clients_section.group(1).strip().split('\n')
            online_count = 0
            
            for line in lines:
                if not line.strip():
                    continue
                    
                # Парсим CSV формат: Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
                parts = line.split(',')
                if len(parts) >= 5:
                    client_name = parts[0].strip()
                    real_ip_port = parts[1].strip()
                    
                    # Извлекаем IP из строки вида "123.45.67.89:12345"
                    real_ip = real_ip_port.split(':')[0] if ':' in real_ip_port else real_ip_port
                    
                    # Получаем VPN IP
                    vpn_ip = self.get_client_vpn_ip(client_name)
                    
                    client_data = {
                        'client': client_name,
                        'key': client_name,
                        'vpn_ip': vpn_ip,
                        'real_ip': real_ip,
                        'comment': '',
                        'reserved_ip': vpn_ip,
                        'bytes_received': parts[2].strip() if len(parts) > 2 else '0',
                        'bytes_sent': parts[3].strip() if len(parts) > 3 else '0',
                        'connected_since': parts[4].strip() if len(parts) > 4 else ''
                    }
                    self.clients_data.append(client_data)
                    self.online_clients.append(client_name)
                    online_count += 1
            
            # Обновление счетчика онлайн
            self.online_label.config(text=f"Clients Online: {online_count}")
            
            # Добавляем также клиентов из CCD (неподключенных)
            self.load_ccd_clients()
        else:
            # Если не нашли подключенных, загружаем CCD клиентов
            self.load_ccd_clients()
            self.online_label.config(text=f"Clients Online: 0")
        
        # Обновление таблицы
        self.update_table()
    
    def load_ccd_clients(self):
        """Загрузка клиентов из CCD файлов"""
        ccd_dir = self.ccd_dir.get()
        
        if os.path.exists(ccd_dir):
            for filename in os.listdir(ccd_dir):
                ccd_path = os.path.join(ccd_dir, filename)
                if os.path.isfile(ccd_path):
                    # Проверяем, есть ли уже такой клиент
                    existing = False
                    for client in self.clients_data:
                        if client['client'] == filename:
                            existing = True
                            break
                    
                    if not existing:
                        # Читаем VPN IP из CCD файла
                        vpn_ip = ""
                        try:
                            with open(ccd_path, 'r') as f:
                                content = f.read()
                                match = re.search(r'ifconfig-push\s+(\d+\.\d+\.\d+\.\d+)', content)
                                if match:
                                    vpn_ip = match.group(1)
                        except:
                            pass
                        
                        client_data = {
                            'client': filename,
                            'key': filename,
                            'vpn_ip': vpn_ip,
                            'real_ip': '',
                            'comment': '',
                            'reserved_ip': vpn_ip
                        }
                        self.clients_data.append(client_data)
    
    def get_client_vpn_ip(self, client_name):
        """Получение VPN IP клиента из CCD файла"""
        ccd_file = os.path.join(self.ccd_dir.get(), client_name)
        
        if os.path.exists(ccd_file):
            try:
                with open(ccd_file, 'r') as f:
                    content = f.read()
                    match = re.search(r'ifconfig-push\s+(\d+\.\d+\.\d+\.\d+)', content)
                    if match:
                        return match.group(1)
            except:
                pass
        
        return ""
    
    def load_demo_data(self):
        """Демонстрационные данные для тестирования"""
        demo_clients = [
            {'client': 'pso', 'key': 'pso', 'vpn_ip': '10.8.0.10', 'real_ip': '192.168.1.100', 'comment': 'Офис', 'reserved_ip': '10.8.0.10'},
            {'client': 'home', 'key': 'home', 'vpn_ip': '10.8.100.4', 'real_ip': 'udp6', 'comment': 'Домашний', 'reserved_ip': '10.8.100.4'},
            {'client': 'work', 'key': 'work', 'vpn_ip': '10.8.0.20', 'real_ip': '10.0.0.50', 'comment': 'Работа', 'reserved_ip': '10.8.0.20'},
            {'client': 'mobile', 'key': 'mobile', 'vpn_ip': '10.8.0.30', 'real_ip': '5.6.7.8', 'comment': 'Мобильный', 'reserved_ip': '10.8.0.30'}
        ]
        
        self.clients_data = demo_clients
        self.online_label.config(text="Clients Online: 3 (демо)")
        self.update_table()
        messagebox.showinfo("Демо режим", "Загружены демонстрационные данные.\nДля реальных данных укажите правильный путь к status.log файлу OpenVPN в настройках.")
    
    def update_table(self):
        """Обновление таблицы клиентов"""
        # Очистка таблицы
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Добавление данных
        for client in self.clients_data:
            # Подсветка онлайн клиентов
            tags = ()
            if client.get('real_ip') and client['real_ip']:
                tags = ('online',)
            
            self.tree.insert("", tk.END, values=(
                client.get('client', ''),
                client.get('key', ''),
                client.get('vpn_ip', ''),
                client.get('real_ip', ''),
                client.get('comment', ''),
                client.get('reserved_ip', '')
            ), tags=tags)
        
        # Настройка цветов
        self.tree.tag_configure('online', background='#d4ffd4')
    
    def show_connected_clients(self):
        """Показать только подключенных клиентов"""
        self.load_status()
        messagebox.showinfo("Информация", f"Подключено клиентов: {len(self.online_clients)}")
    
    def show_clients_list(self):
        """Показать полный список клиентов"""
        self.load_status()
    
    def show_settings(self):
        """Показать/скрыть панель настроек"""
        if self.settings_frame.winfo_ismapped():
            self.settings_frame.pack_forget()
        else:
            self.settings_frame.pack(fill=tk.X, padx=10, pady=5)
    
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
        """Добавление нового клиента"""
        dialog = tk.Toplevel(self.parent)
        dialog.title("Добавить клиента")
        dialog.geometry("400x350")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Имя клиента:").pack(pady=5)
        client_name = ttk.Entry(dialog, width=30)
        client_name.pack(pady=5)
        
        ttk.Label(dialog, text="Ключ:").pack(pady=5)
        client_key = ttk.Entry(dialog, width=30)
        client_key.pack(pady=5)
        
        ttk.Label(dialog, text="VPN IP:").pack(pady=5)
        vpn_ip = ttk.Entry(dialog, width=30)
        vpn_ip.pack(pady=5)
        
        ttk.Label(dialog, text="Комментарий:").pack(pady=5)
        comment = ttk.Entry(dialog, width=30)
        comment.pack(pady=5)
        
        def save_client():
            new_client = {
                'client': client_name.get(),
                'key': client_key.get(),
                'vpn_ip': vpn_ip.get(),
                'real_ip': '',
                'comment': comment.get(),
                'reserved_ip': vpn_ip.get()
            }
            self.clients_data.append(new_client)
            self.update_table()
            dialog.destroy()
            messagebox.showinfo("Успех", "Клиент добавлен")
        
        ttk.Button(dialog, text="Сохранить", command=save_client).pack(pady=20)
    
    def save_clients_list(self):
        """Сохранение списка клиентов в файл"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("Клиент,Ключ,VPN_IP,REAL_IP,комментарий,reserved IP\n")
                    for client in self.clients_data:
                        f.write(f"{client.get('client','')},{client.get('key','')},"
                               f"{client.get('vpn_ip','')},{client.get('real_ip','')},"
                               f"{client.get('comment','')},{client.get('reserved_ip','')}\n")
                messagebox.showinfo("Успех", f"Список сохранен в {file_path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить: {e}")
    
    def create_ccd_file(self):
        """Создание CCD файлов для клиентов"""
        ccd_dir = self.ccd_dir.get()
        
        if not os.path.exists(ccd_dir):
            os.makedirs(ccd_dir)
        
        created = 0
        for client in self.clients_data:
            if client.get('vpn_ip') and client['vpn_ip']:
                ccd_path = os.path.join(ccd_dir, client['client'])
                try:
                    with open(ccd_path, 'w') as f:
                        f.write(f'ifconfig-push {client["vpn_ip"]} {self.mask4ccd.get()}\n')
                        f.write(f'push "route {client["vpn_ip"]} 255.255.255.255"\n')
                    created += 1
                except Exception as e:
                    print(f"Ошибка создания CCD для {client['client']}: {e}")
        
        messagebox.showinfo("Успех", f"Создано CCD файлов: {created}")
    
    def on_client_double_click(self, event):
        """Обработка двойного клика по клиенту"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            values = item['values']
            
            dialog = tk.Toplevel(self.parent)
            dialog.title(f"Редактирование клиента - {values[0]}")
            dialog.geometry("400x400")
            
            ttk.Label(dialog, text="Клиент:").pack(pady=5)
            client_entry = ttk.Entry(dialog, width=30)
            client_entry.insert(0, values[0])
            client_entry.pack(pady=5)
            
            ttk.Label(dialog, text="Ключ:").pack(pady=5)
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
            
            def update_client():
                # Обновление данных
                for client in self.clients_data:
                    if client['client'] == values[0]:
                        client['client'] = client_entry.get()
                        client['key'] = key_entry.get()
                        client['vpn_ip'] = ip_entry.get()
                        client['comment'] = comment_entry.get()
                        client['reserved_ip'] = ip_entry.get()
                        break
                
                self.update_table()
                dialog.destroy()
                messagebox.showinfo("Успех", "Данные клиента обновлены")
            
            ttk.Button(dialog, text="Обновить", command=update_client).pack(pady=10)
            ttk.Button(dialog, text="Отмена", command=dialog.destroy).pack(pady=5)
    
    def ping_vpn(self):
        """Ping VPN IP адреса"""
        ip = self.ping_entry.get()
        if not ip:
            messagebox.showwarning("Предупреждение", "Введите IP адрес для ping")
            return
        
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Pinging {ip}...\n\n")
        
        def ping_thread():
            try:
                result = subprocess.run(
                    ['ping', '-n', '4', ip],
                    capture_output=True,
                    text=True,
                    encoding='cp866'
                )
                
                self.parent.after(0, lambda: self.ping_result.insert(tk.END, result.stdout))
                
                if result.returncode == 0:
                    self.parent.after(0, lambda: self.ping_result.insert(tk.END, "\n✅ Успешный ping!"))
                else:
                    self.parent.after(0, lambda: self.ping_result.insert(tk.END, "\n❌ Хост недоступен!"))
            except Exception as e:
                self.parent.after(0, lambda: self.ping_result.insert(tk.END, f"\nОшибка: {e}"))
        
        threading.Thread(target=ping_thread, daemon=True).start()
    
    def toggle_auto_update(self):
        """Включение/выключение автообновления"""
        if self.auto_update_var.get():
            self.start_auto_update()
        else:
            self.stop_auto_update()
    
    def start_auto_update(self):
        """Запуск автоматического обновления"""
        self.monitoring = True
        self.auto_update()
    
    def stop_auto_update(self):
        """Остановка автоматического обновления"""
        self.monitoring = False
    
    def auto_update(self):
        """Автоматическое обновление статуса"""
        if self.monitoring and self.auto_update_var.get():
            log_path = self.status_file.get()
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self.parse_status_log(content)
                except:
                    pass
            self.parent.after(5000, self.auto_update)

class TextFileViewer:
    """Просмотрщик файлов из определенной папки"""
    def __init__(self, parent, folder_path=None):
        self.parent = parent
        self.folder_path = folder_path or r"C:\Program Files\OpenVPN\config"
        self.current_file = None
        
        self.create_widgets()
        self.load_file_list()
    
    def create_widgets(self):
        # Основной фрейм
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Верхняя панель
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(top_frame, text="Папка:").pack(side=tk.LEFT, padx=5)
        self.folder_var = tk.StringVar(value=self.folder_path)
        folder_entry = ttk.Entry(top_frame, textvariable=self.folder_var, width=50)
        folder_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Обзор", command=self.browse_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Обновить", command=self.load_file_list).pack(side=tk.LEFT, padx=5)
        
        # Панель с файлами и содержимым
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Список файлов
        files_frame = ttk.LabelFrame(content_frame, text="Файлы в папке", width=250)
        files_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # Список файлов с скроллом
        list_frame = ttk.Frame(files_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.files_listbox = tk.Listbox(list_frame, font=('Consolas', 9))
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        files_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.files_listbox.yview)
        files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.files_listbox.config(yscrollcommand=files_scrollbar.set)
        
        self.files_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        # Область просмотра файла
        view_frame = ttk.LabelFrame(content_frame, text="Содержимое файла", padding=5)
        view_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.text_area = scrolledtext.ScrolledText(
            view_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Нижняя панель с информацией
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=5)
        
        self.file_info_label = ttk.Label(info_frame, text="Выберите файл для просмотра", foreground='gray')
        self.file_info_label.pack(side=tk.LEFT)
        
        ttk.Button(info_frame, text="Сохранить изменения", command=self.save_file).pack(side=tk.RIGHT, padx=5)
        ttk.Button(info_frame, text="Обновить", command=self.refresh_current_file).pack(side=tk.RIGHT, padx=5)
    
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_var.set(folder)
            self.load_file_list()
    
    def load_file_list(self):
        """Загрузка списка файлов из папки"""
        self.files_listbox.delete(0, tk.END)
        folder = self.folder_var.get()
        
        if os.path.exists(folder):
            files = glob.glob(os.path.join(folder, "*"))
            
            for file_path in files:
                if os.path.isfile(file_path):
                    filename = os.path.basename(file_path)
                    self.files_listbox.insert(tk.END, filename)
            
            self.file_info_label.config(text=f"Найдено файлов: {len(files)}")
        else:
            self.file_info_label.config(text=f"Папка не найдена: {folder}")
    
    def on_file_select(self, event):
        """Обработка выбора файла"""
        selection = self.files_listbox.curselection()
        if selection:
            filename = self.files_listbox.get(selection[0])
            file_path = os.path.join(self.folder_var.get(), filename)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(1.0, content)
                self.current_file = file_path
                
                # Информация о файле
                file_size = os.path.getsize(file_path)
                self.file_info_label.config(text=f"Файл: {filename} | Размер: {file_size} байт")
                
            except Exception as e:
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(1.0, f"Ошибка чтения файла:\n{str(e)}")
                self.file_info_label.config(text=f"Ошибка: {filename}")
    
    def save_file(self):
        """Сохранение изменений в файле"""
        if self.current_file:
            try:
                content = self.text_area.get(1.0, tk.END).rstrip()
                with open(self.current_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Успех", f"Файл сохранен: {os.path.basename(self.current_file)}")
                self.file_info_label.config(text=f"Сохранен: {os.path.basename(self.current_file)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{str(e)}")
    
    def refresh_current_file(self):
        """Обновление текущего файла"""
        if self.current_file:
            scroll_pos = self.text_area.yview()
            self.on_file_select(None)
            self.text_area.yview_moveto(scroll_pos[0])

class CombinedApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenVPN Status Monitor + File Viewer")
        self.root.geometry("1300x800")
        
        # Создание вкладок
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Вкладка монитора OpenVPN
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text="OpenVPN Status Monitor")
        self.monitor = OpenVPNStatusMonitor(self.monitor_frame)
        
        # Вкладка с текстовым редактором для файлов из папки
        self.editor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.editor_frame, text="Файлы конфигурации")
        self.file_viewer = TextFileViewer(self.editor_frame, r"C:\Program Files\OpenVPN\config")
        
        # Настройка закрытия
        root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def on_closing(self):
        if hasattr(self.monitor, 'stop_auto_update'):
            self.monitor.stop_auto_update()
        self.root.destroy()

def main():
    root = tk.Tk()
    app = CombinedApplication(root)
    root.mainloop()

if __name__ == "__main__":
    main()
