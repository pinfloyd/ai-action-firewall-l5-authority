FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --disable-pip-version-check --no-cache-dir -r /app/requirements.txt

COPY authority_server.py /app/authority_server.py

ENV HOST=0.0.0.0
ENV PORT=8787

EXPOSE 8787

CMD ["python","/app/authority_server.py"]