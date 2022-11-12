FROM python:3.9-slim

ENV HOME /app
WORKDIR $HOME
COPY . ./
RUN pip install --no-cache-dir -r requirements.txt
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 app:flask_app
