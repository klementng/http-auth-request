FROM python:3.10

WORKDIR /app
COPY . .

RUN pip install -r /app/requirements.txt

ENTRYPOINT ["python3","/app/main.py"]
CMD ["server", "start"]