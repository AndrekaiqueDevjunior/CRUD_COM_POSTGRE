import psycopg2
from psycopg2 import OperationalError, Error

try:
    # Conectar ao banco de dados PostgreSQL
    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="root",
        host="localhost"
    )
    
    # Cria um cursor para operações no banco de dados
    cur = conn.cursor()
    
    # Exemplo: verificar a versão do PostgreSQL
    cur.execute("SELECT version()")
    db_version = cur.fetchone()
    print(f"Conexão bem-sucedida! Versão do PostgreSQL: {db_version}")
    
    # Fechar o cursor e a conexão
    cur.close()
    conn.close()

except OperationalError as e:
    print(f"Erro de conexão: {e}")

except Error as e:
    print(f"Erro no PostgreSQL: {e}")

except Exception as e:
    print(f"Erro desconhecido: {e}")
