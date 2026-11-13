# VulnWatch를 클린 환경에서 다시 만들어 보기 위한 이미지 (선택 사항. 평소 개발은 로컬 venv로 한다)
# 교육용 더미 데이터만 담는다. .env와 var/는 이미지에 넣지 않는다.
#
#   docker build -t vulnwatch .
#   docker run --rm vulnwatch python -m pytest tests -q            배선 테스트 (LLM 호출 없음)
#   docker run --rm -p 8000:8000 --env-file .env vulnwatch         서버 실행. 화면은 http://127.0.0.1:8000/ui/
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /app

# 의존성을 먼저 설치해 코드가 바뀌어도 이 층을 다시 쓰게 한다
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 필요한 것만 골라 넣는다. .env(비밀 값), var/(실행 중 생기는 DB), reference/는 넣지 않는다
COPY app.py ./
COPY src ./src
COPY data ./data
COPY web ./web
COPY tests ./tests
COPY evaluation ./evaluation

EXPOSE 8000

# 컨테이너 밖에서 접속할 수 있게 0.0.0.0으로 연다. Bedrock 자격 증명은 실행할 때 --env-file로 준다
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
