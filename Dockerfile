# Usa uma imagem oficial do Python slim para ser leve
FROM python:3.11-slim

# Evita que o Python grave arquivos .pyc e força log em tempo real sem buffer
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Instala dependências do sistema e a ferramenta Nuclei (Go)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    git \
    ca-certificates \
    && wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && apt-get install -y unzip \
    && unzip nuclei_3.1.0_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho no container
WORKDIR /app

# Copia e instala as dependências do Python
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o código da aplicação para o container
COPY . /app/

# Cria pasta de relatórios
RUN mkdir -p /app/reports

# Porta exposta para a API FastAPI
EXPOSE 8000

# Comando padrão ao subir o container
CMD ["python3", "dashboard.py"]
