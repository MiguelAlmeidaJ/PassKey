# PassKey Web (PHP + MariaDB)

Versão web independente do aplicativo Windows, destinada a hospedagem compartilhada DirectAdmin em https://passkey.anoar.com.br.

## Requisitos

- PHP 8.1+ com PDO MySQL, extensão openssl, sessões e suporte a Argon2id (`password_hash(..., PASSWORD_ARGON2ID)`).
- MariaDB ou MySQL no mesmo servidor PHP.
- HTTPS válido e obrigatório.
- Banco MySQL criado no DirectAdmin e usuário com permissões SELECT/INSERT/UPDATE/DELETE. Para importar `schema.sql`, o usuário também precisa de CREATE (retire depois).
- Navegador moderno com Web Crypto API.

## Publicação no DirectAdmin

1. Crie o subdomínio `passkey.anoar.com.br` no DirectAdmin, configure o DNS e emita/ative SSL (Let's Encrypt) para ele.
2. No DirectAdmin, crie o banco e o usuário MariaDB. O host utilizado pelo PHP costuma ser `localhost`.
3. Importe o arquivo `web/schema.sql` no phpMyAdmin **do banco correto**.
4. Copie `web/config.example.php` para `web/config.php`, edite o nome exato do banco, usuário e senha.
5. Hospede `web/public/` **como raiz de documentos exclusiva do subdomínio** (Document Root). É fundamental que `web/config.php` e `web/schema.sql` fiquem FORA da pasta pública. Não publique o repositório inteiro dentro da raiz web.
6. Abra `https://passkey.anoar.com.br`, configure sua senha mestra forte (16 caracteres ou mais), salve um registro de teste, bloqueie, reabra e confirme que o registro continua disponível.
7. Faça backup criptografado do banco inteiro, incluindo `web_vault` (com salt/verificador) e `web_entries`, e teste a restauração. Sem a senha mestra os dados são irrecuperáveis.

### Se o painel não permitir ajustar o Document Root

Não coloque `config.php` na pasta pública. A alternativa é fazer upload **somente** de `web/public/index.php`, `web/public/api.php`, `web/public/app.js` e `web/public/style.css` para o diretório público e ajustar o caminho em `api.php` para apontar para um arquivo de configuração PHP real **fora** da raiz pública. Se não conseguir garantir isso, não publique.

## Criptografia e limitações

O navegador cifra registros usando AES-256-GCM; a chave é derivada com PBKDF2-SHA256, 600.000 iterações e salt aleatório. Títulos, IPs, nomes de usuário, notas e senhas dos registros são cifrados antes de chegar ao PHP. A senha mestra é transmitida **ao servidor PHP por HTTPS para autenticação** e comparada a um hash Argon2id; portanto, esta solução **não é zero-knowledge em relação ao servidor**. Um servidor comprometido ou JavaScript alterado pode capturar a senha mestra. O hoster e o operador do site precisam ser confiáveis.

Esta versão web usa tabelas próprias `web_vault`/`web_entries`, e **não abre automaticamente os cofres Python** anteriores (`vault_config`/`vault_entries`). Não apague bancos antigos.

**MVP não auditado:** sem MFA, proteção abrangente de brute force na borda, verificação independente de integridade do frontend, recuperação de chave, importação, backups automáticos, autofill ou sincronização offline. Não guarde credenciais críticas antes de uma revisão de segurança independente. Configure proteção adicional via hospedagem (WAF, limitação de tentativas, controle de acesso). Não exponha phpMyAdmin, arquivos de backup ou configuração no subdomínio.
