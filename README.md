# PassKey

Cofre de senhas e acessos em um aplicativo desktop Windows (Python/Tkinter), com dados armazenados em MySQL de forma criptografada no cliente.

## Segurança

- Criptografia autenticada **AES-256-GCM** por registro, com nonce aleatório.
- Chave derivada da senha mestra por **Argon2id** e salt aleatório de 16 bytes.
- Todos os campos dos registros (inclusive títulos, IPs e nomes de usuário) são criptografados antes de chegar ao banco.
- A senha mestra e a chave de descriptografia **nunca são gravadas no banco**.
- A primeira execução cria o cofre; as seguintes exigem a senha mestra correta.
- **Não existe recuperação da senha mestra**. Faça backups seguros do MySQL.
- Não expor MySQL na internet. Use um túnel SSH e acesse pelo endereço local `127.0.0.1`.
- Este é um MVP, não um gerenciador auditado. Não migre credenciais críticas até auditar código, dependências e procedimentos de backup/restauração.

## Instalação (Windows)

Requisitos: Python 3.11+; MySQL 8; acesso SSH ao servidor.

```powershell
git clone https://github.com/MiguelAlmeidaJ/PassKey.git
cd PassKey
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Crie o banco e usuário MySQL de permissões mínimas:

```sql
CREATE DATABASE passkey CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'passkey'@'localhost' IDENTIFIED BY 'SUBSTITUA_POR_SENHA_FORTE';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE ON passkey.* TO 'passkey'@'localhost';
```

Se o usuário se conecta ao MySQL a partir de um container ou outra origem, ajuste a conta host de acordo com a topologia. O exemplo acima pressupõe cliente MySQL no próprio servidor através do túnel SSH.

Abra um terminal e mantenha o túnel ativo:

```powershell
ssh -N -L 127.0.0.1:13306:127.0.0.1:3306 usuario@seu-servidor
```

No arquivo `.env` configure `DB_HOST=127.0.0.1`, `DB_PORT=13306`, `DB_USER`, `DB_PASSWORD` e `DB_NAME`. Nunca versionar `.env`.

Execute:

```powershell
python app.py
```

## Gerar executável

```powershell
pip install pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name PassKey app.py
```

O executável estará em `dist\PassKey.exe`. Mantenha `.env` na mesma pasta do executável. **Não embuta segredos no executável**. Dependências e artefatos devem ser verificados antes do uso.

## Backup

Use um backup consistente do banco `passkey` (`mysqldump --single-transaction passkey`). Proteja e teste restaurações. O backup conterá dados cifrados, mas o salt e demais parâmetros devem ser preservados para que a senha mestra consiga reabrir o cofre.

## Limitações da primeira versão

Aplicativo destinado a um único cofre, uso pessoal, armazenamento online com conexão ativa. Sem compartilhamento, sincronização de conflitos, anexos, biometria, preenchimento automático, rotação de senha ou recuperação de senha mestra. A cópia para a área de transferência pode ficar acessível a outros aplicativos; limpe-a após o uso.
