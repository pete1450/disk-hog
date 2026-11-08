FROM python:3.13-slim
WORKDIR /app
COPY app.py /app/app.py
# No pip packages needed - stdlib only.
EXPOSE 8081
CMD ["python3", "app.py"]
