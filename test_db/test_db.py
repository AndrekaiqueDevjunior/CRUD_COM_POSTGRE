import psycopg2
from psycopg2 import OperationalError

# Defina a URL de conexão
DATABASE_URL = "postgres://default:b6U4HojAfcCO@ep-cool-snow-a4r4ma9e-pooler.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require"

def test_connection():
    try:
        # Conectar ao banco de dados
        conn = psycopg2.connect(DATABASE_URL)
        print("Conexão bem-sucedida!")
    except OperationalError as e:
        print(f"Erro na conexão: {e}")
    finally:
        # Fechar a conexão
        if conn:
            conn.close()

if __name__ == "__main__":
    test_connection()
