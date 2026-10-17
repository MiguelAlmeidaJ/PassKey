"use strict";
const el = id => document.getElementById(id);
const utf8 = new TextEncoder(), decoder = new TextDecoder();
let state, cryptoKey, records = [], editing = null;
function msg(text) { el("status").textContent = text; }
function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
async function keyFrom(password, salt) {
  const material = await crypto.subtle.importKey("raw", utf8.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: unb64(salt), iterations: 600000, hash: "SHA-256" },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt","decrypt"]);
}
async function encrypt(value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const bytes = utf8.encode(JSON.stringify(value));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv}, cryptoKey, bytes));
  return JSON.stringify({v:1,iv:b64(iv),ct:b64(ct)});
}
async function decrypt(blob) {
  const data = JSON.parse(blob);
  if (data.v !== 1) throw Error("Formato não suportado");
  const plain = await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(data.iv)}, cryptoKey, unb64(data.ct));
  return JSON.parse(decoder.decode(plain));
}
async function api(action, body=null) {
  const response = await fetch("api.php?action="+encodeURIComponent(action), {
    method: body === null ? "GET" : "POST",
    headers: {"Content-Type":"application/json"},
    credentials:"same-origin",cache:"no-store",
    ...(body === null ? {} : {body:JSON.stringify({...body,csrf:state.csrf})})
  });
  const result = await response.json();
  if (!response.ok) throw Error(result.error || "Falha na solicitação");
  return result;
}
async function init() {
  if (!window.isSecureContext || !crypto?.subtle) throw Error("É necessário HTTPS para usar o cofre.");
  state = await api("state");
  el("authTitle").textContent = state.configured ? "Desbloquear cofre" : "Criar cofre";
  el("authHint").textContent = state.configured ? "Informe sua senha mestra." : "Primeiro acesso: crie uma senha mestra de pelo menos 16 caracteres. Guarde-a em local seguro.";
  el("unlockBtn").textContent = state.configured ? "Desbloquear" : "Criar cofre";
  if (state.authenticated) {
    el("authHint").textContent = "Sessão ativa. Digite a senha mestra para abrir o conteúdo criptografado.";
    el("unlockBtn").textContent = "Abrir cofre";
  }
}
async function unlock(event) {
  event.preventDefault();
  const pass = el("master").value;
  if (pass.length < 16) { msg("A senha deve ter pelo menos 16 caracteres."); return; }
  el("unlockBtn").disabled = true;
  try {
    if (!state.configured) {
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      cryptoKey = await keyFrom(pass, salt);
      const check = await encrypt({check:"PassKey browser vault v1"});
      await api("setup",{password:pass,salt:Array.from(unb64(salt)).map(x=>x.toString(16).padStart(2,"0")).join(""),check});
      state.configured = true;
    } else {
      const saltBytes = Uint8Array.from(state.salt.match(/../g).map(x=>parseInt(x,16)));
      cryptoKey = await keyFrom(pass,b64(saltBytes));
      const result = state.authenticated ? {check:state.check} : await api("login",{password:pass});
      const check = await decrypt(result.check);
      if (check.check !== "PassKey browser vault v1") throw Error("Chave mestra inválida");
    }
    el("master").value = "";
    el("auth").hidden = true; el("vault").hidden = false; el("logout").hidden = false;
    await refresh();
    msg("Cofre desbloqueado.");
  } catch(error) {cryptoKey = null; msg("Erro: "+error.message);}
  finally {el("unlockBtn").disabled = false;}
}
async function refresh() {
  const response = await api("list",{});
  records = [];
  for (const entry of response.entries) {
    const data = await decrypt(entry.payload);
    records.push({id:Number(entry.id),data});
  }
  render();
}
function text(tag,value) {
  const element = document.createElement(tag);
  element.textContent = value || "";
  return element;
}
function render() {
  const root=el("entries");
  root.replaceChildren();
  const q=el("search").value.toLocaleLowerCase();
  for(const record of records) {
    const d=record.data;
    if(![d.title,d.category,d.username,d.host,d.url].join(" ").toLocaleLowerCase().includes(q)) continue;
    const card=document.createElement("article");card.className="entry";
    const category=text("span",d.category);category.className="tag";card.append(category);
    card.append(text("h3",d.title),text("p",d.username || ""),text("p",d.host || d.url || ""));
    const buttons=document.createElement("div");buttons.className="actions";
    for (const [title,handler,className] of [
      ["Copiar usuário",()=>copy(d.username),"secondary"],
      ["Copiar senha",()=>copy(d.password),"secondary"],
      ["Editar",()=>edit(record),"secondary"],
      ["Excluir",()=>remove(record),"danger"]
    ]) {
      const button=text("button",title);button.type="button";button.className=className;button.addEventListener("click",handler);
      buttons.append(button);
    }
    card.append(buttons);root.append(card);
  }
  if(!root.children.length)root.append(text("p","Nenhum acesso encontrado."));
}
async function copy(value) {
  if(!value){msg("Campo vazio.");return;}
  try{await navigator.clipboard.writeText(value);msg("Copiado. Limpe a área de transferência após utilizar.");}
  catch{msg("Não foi possível copiar.");}
}
function edit(record=null) {
  editing=record?.id ?? null;
  el("entryForm").reset();
  el("editorTitle").textContent=record?"Editar acesso":"Novo acesso";
  if(record)for(const [name,value] of Object.entries(record.data)) {
    const field=el("entryForm").elements.namedItem(name);
    if(field)field.value=value;
  }
  el("editor").showModal();
}
async function save(event) {
  event.preventDefault();
  const data=Object.fromEntries(new FormData(event.target).entries());
  if(!data.title.trim()){msg("Informe o nome do acesso.");return;}
  try {
    await api("save",{id:editing,payload:await encrypt(data)});
    el("editor").close();await refresh();msg("Acesso salvo.");
  }catch(error){msg(error.message);}
}
async function remove(record) {
  if(!confirm("Excluir este acesso definitivamente?"))return;
  try{await api("delete",{id:record.id});await refresh();msg("Acesso excluído.");}
  catch(error){msg(error.message);}
}
async function logout() {
  try{await api("logout",{});}catch{}
  cryptoKey=null;records=[];location.reload();
}
el("authForm").addEventListener("submit",unlock);
el("newBtn").addEventListener("click",()=>edit());
el("cancel").addEventListener("click",()=>el("editor").close());
el("entryForm").addEventListener("submit",save);
el("search").addEventListener("input",render);
el("logout").addEventListener("click",logout);
init().catch(error=>msg(error.message));
