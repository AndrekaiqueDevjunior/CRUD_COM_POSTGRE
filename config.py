import os

class Config:
    # Configurações de upload
    UPLOAD_FOLDER = 'uploads'
    
    # Configurações do Dropbox Sign
    DROPBOX_ACCESS_TOKEN = 'NWNiOTMxOGFkOGVjMDhhNTAxZN2NkNjgxMjMwOWJiYTEzZTBmZGUzMjMThhMzYyMzc='
    DROPBOX_REFRESH_TOKEN = 'hNTI2MTFmM2VmZDQxZTZjOWRmZmFjZmVmMGMyNGFjMzI2MGI5YzgzNmE3'
    DROPBOX_CLIENT_ID = 'cc91c61d00f8bb2ece1428035716b'
    DROPBOX_CLIENT_SECRET = '1d14434088507ffa390e6f5528465'
    DROPBOX_UPLOAD_PATH = '/Vercel/Imagens'
    
    # Outras configurações
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_default_secret_key')
    DEBUG = os.environ.get('DEBUG', True)
