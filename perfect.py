import cv2
import pytesseract
import os
from datetime import datetime
from gtts import gTTS
import pygame
from langdetect import detect
import pyttsx3
import threading
import time

# Cấu hình đường dẫn
IMAGE_FOLDER = ""  # Để trống như yêu cầu, sẽ dùng thư mục hiện tại
AUDIO_FOLDER = ""  # Để trống như yêu cầu

# Cấu hình Tesseract nếu cần
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

class SmartGlassesReader:
    def __init__(self):
        # Khởi tạo pygame cho phát âm thanh
        pygame.mixer.init()
        
        # Khởi tạo pyttsx3 cho offline TTS (backup)
        self.engine = pyttsx3.init()
        self.engine.setProperty('rate', 150)  # Tốc độ đọc
        
        # Camera
        self.cap = cv2.VideoCapture(0)
        
    def capture_image(self):
        """Chụp ảnh từ camera"""
        ret, frame = self.cap.read()
        if ret:
            # Tạo tên file với timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}.jpg"
            filepath = os.path.join(IMAGE_FOLDER, filename)
            
            # Lưu ảnh
            cv2.imwrite(filepath, frame)
            print(f"Đã chụp ảnh: {filepath}")
            return filepath
        return None
    
    def extract_text_from_image(self, image_path):
        """Trích xuất văn bản từ ảnh sử dụng OCR"""
        try:
            # Đọc ảnh
            img = cv2.imread(image_path)
            
            # Tiền xử lý ảnh để cải thiện OCR
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Tăng độ tương phản
            gray = cv2.convertScaleAbs(gray, alpha=1.5, beta=0)
            
            # OCR với cả tiếng Anh và tiếng Việt
            # Cần cài đặt gói ngôn ngữ tiếng Việt cho Tesseract
            text = pytesseract.image_to_string(gray, lang='eng+vie')
            
            # Loại bỏ khoảng trắng thừa
            text = ' '.join(text.split())
            
            print(f"Văn bản trích xuất: {text[:100]}...")  # In 100 ký tự đầu
            return text
            
        except Exception as e:
            print(f"Lỗi khi trích xuất văn bản: {e}")
            return ""
    
    def detect_language(self, text):
        """Phát hiện ngôn ngữ của văn bản"""
        try:
            lang = detect(text)
            return 'vi' if lang == 'vi' else 'en'
        except:
            # Mặc định là tiếng Việt nếu không phát hiện được
            return 'vi'
    
    def text_to_speech_gtts(self, text, output_path):
        """Chuyển văn bản thành giọng nói sử dụng gTTS (cần internet)"""
        try:
            # Phát hiện ngôn ngữ
            lang = self.detect_language(text)
            
            # Tạo file âm thanh
            tts = gTTS(text=text, lang=lang, slow=False)
            tts.save(output_path)
            
            print(f"Đã tạo file âm thanh: {output_path}")
            return True
            
        except Exception as e:
            print(f"Lỗi khi tạo file âm thanh với gTTS: {e}")
            return False
    
    def text_to_speech_pyttsx3(self, text, output_path):
        """Chuyển văn bản thành giọng nói sử dụng pyttsx3 (offline)"""
        try:
            # Lưu thành file
            self.engine.save_to_file(text, output_path)
            self.engine.runAndWait()
            
            print(f"Đã tạo file âm thanh offline: {output_path}")
            return True
            
        except Exception as e:
            print(f"Lỗi khi tạo file âm thanh với pyttsx3: {e}")
            return False
    
    def play_audio(self, audio_path):
        """Phát file âm thanh qua loa"""
        try:
            # Load và phát file âm thanh
            pygame.mixer.music.load(audio_path)
            pygame.mixer.music.play()
            
            # Đợi cho đến khi phát xong
            while pygame.mixer.music.get_busy():
                pygame.time.Clock().tick(10)
                
            print("Đã phát xong âm thanh")
            
        except Exception as e:
            print(f"Lỗi khi phát âm thanh: {e}")
    
    def process_image_to_speech(self, image_path):
        """Xử lý toàn bộ quy trình từ ảnh đến giọng nói"""
        # Trích xuất văn bản
        text = self.extract_text_from_image(image_path)
        
        if not text:
            print("Không tìm thấy văn bản trong ảnh")
            return
        
        # Tạo tên file âm thanh
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        audio_filename = f"audio_{timestamp}.mp3"
        audio_path = os.path.join(AUDIO_FOLDER, audio_filename)
        
        # Thử tạo file âm thanh với gTTS trước (chất lượng tốt hơn)
        success = self.text_to_speech_gtts(text, audio_path)
        
        # Nếu không có internet, dùng pyttsx3
        if not success:
            audio_path = audio_path.replace('.mp3', '.wav')
            success = self.text_to_speech_pyttsx3(text, audio_path)
        
        # Phát âm thanh
        if success:
            self.play_audio(audio_path)
    
    def run(self):
        """Chạy chương trình chính"""
        print("Kính thông minh đã sẵn sàng!")
        print("Nhấn SPACE để chụp và đọc")
        print("Nhấn Q để thoát")
        
        while True:
            ret, frame = self.cap.read()
            if not ret:
                break
            
            # Hiển thị hình ảnh từ camera
            cv2.imshow('Smart Glasses View', frame)
            
            key = cv2.waitKey(1) & 0xFF
            
            # Nhấn SPACE để chụp và xử lý
            if key == ord(' '):
                print("\nĐang xử lý...")
                
                # Chụp ảnh
                image_path = self.capture_image()
                
                if image_path:
                    # Xử lý trong thread riêng để không block camera
                    thread = threading.Thread(
                        target=self.process_image_to_speech,
                        args=(image_path,)
                    )
                    thread.start()
            
            # Nhấn Q để thoát
            elif key == ord('q'):
                break
        
        # Dọn dẹp
        self.cap.release()
        cv2.destroyAllWindows()
        pygame.mixer.quit()

# Hàm main để test từng phần
def test_with_existing_image(image_path):
    """Test với ảnh có sẵn"""
    reader = SmartGlassesReader()
    reader.process_image_to_speech(image_path)

if __name__ == "__main__":
    # Khởi động ứng dụng
    glasses = SmartGlassesReader()
    glasses.run()
    
    # Hoặc test với ảnh có sẵn:
    test_with_existing_image("D:/Documents/ảnh/b3285fe046332d85c5ed0d3474e08949.jpg")
