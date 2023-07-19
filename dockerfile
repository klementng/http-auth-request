FROM python:3.10

WORKDIR /app
COPY . .

RUN pip install -r /app/requirements.txt
ENV PATH="$PATH:/app/scripts"

CMD ["server", "start"]
