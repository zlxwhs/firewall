import ollama

response = ollama.chat(
    model = "gemma3:1b",
    messages = [
        {
            "role" : "system",
            "content" : "당신은 친절한 한국어 비서입니다. 최대한 쉽게 이해할 수 있도록 설명해주세요."
        },
        {
            "role" : "user",
            "content" : "파이썬에서 리스트를 정렬하는 방법을 설명해 주세요."
        }
    ]
)

print(response['message']['content'])