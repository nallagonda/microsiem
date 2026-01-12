FROM python:3.12.11-slim

WORKDIR /app

COPY micro_siem_backend/ .

COPY micro_siem_ui/siem_ui/dist ./dist

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]