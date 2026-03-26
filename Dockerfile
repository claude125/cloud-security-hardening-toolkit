FROM python:3.11-slim

LABEL maintainer="Claude Dusengimana <dusenge125@gmail.com>"
LABEL description="Cloud Security Hardening Toolkit — AWS & Azure CIS Benchmark Auditor"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports

ENTRYPOINT ["python"]
CMD ["scripts/aws_audit.py"]
