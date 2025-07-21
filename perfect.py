import cv2
import pytesseract

# Nếu cần chỉ định path tesseract:
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
print(pytesseract.get_tesseract_version())

img = cv2.imread('book.jpg')
text = pytesseract.image_to_string(img, lang='eng')
print(text)

# Khởi tạo camera
cap = cv2.VideoCapture(0)

# Chọn ngôn ngữ tiếng Việt nếu đã cài (bỏ lang='vie' nếu chưa cài)
OCR_LANG = 'eng'  # đổi 'vie' nếu muốn tiếng Việt

while True:
    ret, frame = cap.read()
    if not ret:
        break

    # Resize nhỏ cho nhẹ, nhận dạng nhanh hơn
    scale = 0.75
    small = cv2.resize(frame, None, fx=scale, fy=scale)

    # Chuyển xám
    gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)

    # OCR với thông tin box
    data = pytesseract.image_to_data(gray, output_type=pytesseract.Output.DICT, lang=OCR_LANG)

    n_boxes = len(data['level'])
    extracted_text = []

    for i in range(n_boxes):
        text = data['text'][i].strip()
        try:
            conf = int(data['conf'][i])
        except:
            conf = 0
        if conf > 60 and text != '':
            (x, y, w, h) = (data['left'][i], data['top'][i], data['width'][i], data['height'][i])

            cv2.rectangle(small, (x, y), (x + w, y + h), (0, 255, 0), 2)

            cv2.putText(small, text, (x, y - 5),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 1, cv2.LINE_AA)

            extracted_text.append(text)
            
    cv2.imshow('Real-Time OCR Camera', small)

    if extracted_text:
        print("Detected Text:", ' '.join(extracted_text))

    # Nhấn 'q' để thoát
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()

