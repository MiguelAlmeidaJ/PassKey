<?php
declare(strict_types=1);
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    http_response_code(403);
    exit('PassKey exige HTTPS.');
}
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
header('Strict-Transport-Security: max-age=31536000');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
?>
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PassKey • Cofre de acessos</title>
<link rel="stylesheet" href="style.css">
<script src="app.js" defer></script>
</head>
<body>
<main class="shell">
<header><div class="brand"><span class="symbol">◆</span><div><h1>PassKey</h1><small>Cofre de acessos</small></div></div><button id="logout" hidden>Sair e bloquear</button></header>
<section id="auth" class="panel auth">
<h2 id="authTitle">Abrir cofre</h2>
<p id="authHint">Digite sua senha mestra para desbloquear.</p>
<form id="authForm">
<label>Senha mestra<input id="master" type="password" autocomplete="current-password" minlength="16" required></label>
<button type="submit" id="unlockBtn">Desbloquear</button>
</form>
<p class="note">Sua senha mestra é necessária para entrar. Não existe recuperação automática da chave de criptografia.</p>
</section>
<section id="vault" hidden>
<div class="toolbar"><div><h2>Seus acessos</h2><p>Senhas, servidores, painéis e informações importantes.</p></div><button id="newBtn">+ Novo acesso</button></div>
<input id="search" type="search" placeholder="Buscar por nome, categoria, IP ou usuário..." aria-label="Buscar acessos">
<div id="entries" class="entries"></div>
</section>
<p id="status" role="status" aria-live="polite"></p>
</main>
<dialog id="editor"><form id="entryForm"><h2 id="editorTitle">Novo acesso</h2>
<div class="fields">
<label>Nome / identificação<input name="title" maxlength="200" required></label>
<label>Categoria<select name="category"><option>Servidor</option><option>Site</option><option>Banco de dados</option><option>E-mail</option><option>Outros</option></select></label>
<label>URL / endereço<input name="url" maxlength="2000"></label>
<label>IP / Hostname<input name="host" maxlength="500"></label>
<label>Porta<input name="port" maxlength="20"></label>
<label>Usuário / login<input name="username" maxlength="500"></label>
<label>Senha<input name="password" type="password" autocomplete="off"></label>
<label>Observações<textarea name="notes" rows="4"></textarea></label>
</div>
<div class="actions"><button type="button" id="cancel" class="secondary">Cancelar</button><button type="submit">Salvar acesso</button></div>
</form></dialog>
</body></html>
