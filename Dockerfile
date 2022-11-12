FROM python:3.9-slim

ENV HOME /app
WORKDIR $HOME
COPY . ./
EXPOSE 3000
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "app.py"]
