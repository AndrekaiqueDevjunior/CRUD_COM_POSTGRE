import psycopg2

# Função para conectar ao banco de dados
def connect_to_postgres():
    try:
        conn = psycopg2.connect(
            dbname="postgres",
            user="postgres",
            password="root",
            host="localhost",
            port="5432"
        )
        return conn
    except Exception as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return None

# Função para consultar um usuário pelo ID
def get_user_by_id(user_id):
    conn = connect_to_postgres()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, username, profile_picture FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            cur.close()
            conn.close()
            return user
        except Exception as e:
            print(f"Erro ao executar a consulta: {e}")
            return None
    return None

def main():
    user_id = 1  # Substitua com o ID do usuário que você deseja testar
    user = get_user_by_id(user_id)
    
    if user:
        print(f"Tipo de dado retornado: {type(user)}")
        print("Conteúdo retornado:")
        print(user)
        
        if isinstance(user, tuple):
            print("O retorno é uma tupla. Acessando os elementos:")
            print(f"ID: {user[0]}")
            print(f"Username: {user[1]}")
            print(f"Profile Picture: {user[2]}")
    else:
        print("Nenhum usuário encontrado ou erro na consulta.")

if __name__ == "__main__":
    main()
