# Use a imagem base do Python
FROM python:3.11-slim

# Defina o diretório de trabalho
WORKDIR /app

# Copie o arquivo de requisitos para o contêiner
COPY requirements.txt .

# Instale as dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copie o restante dos arquivos da aplicação para o diretório de trabalho
COPY . .

# Copie o arquivo .env
COPY .env .env

# Exponha a porta que a aplicação usará
EXPOSE 5000

# Defina o comando padrão para iniciar a aplicação
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
