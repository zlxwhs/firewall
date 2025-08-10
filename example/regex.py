import re

text1 = "오늘은 날씨가 맑고 기분이 좋습니다."
match = re.search("날씨", text1)
print("1. 특정 단어 찾기:", "찾았습니다" if match else "찾을 수 없습니다.")

text2 = "이메일은 test@example.com 또는 hello@domain.co.kr로 보내주세요."
email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
emails = re.findall(email_pattern, text2)
print("2. 이메일 주소 추출:", emails)

text3 = "나는 10개의 사과를 샀고, 가격은 3000원입니다."
numbers = re.findall(r"\d+", text3)
print("4. 숫자 찾기:", numbers)

text4 = "010-1234-5678"
phone_pattern = r"^\d{3}-\d{4}-\d{4}$"
print(
    "4. 전화번호 형식 확인:",
    "올바른 형식" if re.match(phone_pattern, text4) else "잘못된 형식",
)

