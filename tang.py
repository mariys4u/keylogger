import os

def increase_exe_size(file_path, target_size_mb):
    target_size_bytes = target_size_mb * 1024 * 1024  # Chuyển đổi MB thành bytes
    
    # Kiểm tra kích thước hiện tại của tệp
    current_size = os.path.getsize(file_path)
    
    if current_size >= target_size_bytes:
        print("Tệp đã lớn hơn kích thước mục tiêu.")
        return
    
    # Tính toán số bytes cần thêm
    bytes_to_add = target_size_bytes - current_size
    
    # Mở tệp và thêm ký tự null
    with open(file_path, 'ab') as f:  # 'ab' để mở tệp ở chế độ nhị phân
        f.write(b'\0' * bytes_to_add)  # Ghi ký tự null

    print(f"Đã thêm {bytes_to_add} ký tự null vào tệp.")

# Thay đổi đường dẫn tệp và kích thước mục tiêu tại đây
file_path = r'C:\Users\tuan\Desktop\keylogger\dist\keylogger.exe'  # Đường dẫn đến tệp .exe của bạn
target_size_mb = 700  # Kích thước mục tiêu

increase_exe_size(file_path, target_size_mb)
