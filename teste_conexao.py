"""Diagnóstico de acesso remoto ao MariaDB/MySQL (não consulta dados do cofre).

Uso:
    python teste_conexao.py

Solicita credenciais no terminal sem salvá-las. Este teste pode negociar TLS,
mas NÃO valida a identidade do servidor; não use para transferir segredos.
"""
import getpass
import mysql.connector


def main():
    print("=== Diagnóstico de conexão MariaDB / ValueHost ===")
    host = input("Host [br64-da.valueserver.net.br]: ").strip() or "br64-da.valueserver.net.br"
    port_input = input("Porta [3306]: ").strip()
    try:
        port = int(port_input) if port_input else 3306
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        print("Porta inválida.")
        return 1

    user = input("Usuário MySQL: ").strip()
    if not user:
        print("Usuário obrigatório.")
        return 1
    password = getpass.getpass("Senha MySQL (não será exibida): ")
    if not password:
        print("Senha obrigatória.")
        return 1

    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            connection_timeout=10,
            ssl_disabled=False,
        )
        print("\n[OK] Conexão e autenticação concluídas.")

        cursor = connection.cursor()
        cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
        status = cursor.fetchone()
        cipher = status[1] if status and len(status) >= 2 else ""
        if cipher:
            print(f"[OK] TLS negociado (cifra: {cipher}).")
            print("[AVISO] A identidade do servidor NÃO foi verificada neste teste.")
        else:
            print("[AVISO] Não foi possível confirmar TLS nesta conexão.")
        print("\nO PassKey continuará exigindo TLS com certificado verificado para conexão remota.")
        return 0
    except mysql.connector.Error as exc:
        print(f"\n[ERRO] Falha de conexão/autenticação: {exc}")
        print("Confira hosts permitidos (IP público), usuário, senha, porta e políticas TLS.")
        return 1
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
