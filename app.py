import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.exceptions import InvalidTag
from crypto import CHECK, derive_key, encrypt, decrypt, encrypt_record, decrypt_record
from storage import Storage

FIELDS = (
    ("title", "Nome / identificação"),
    ("category", "Categoria"),
    ("url", "URL / endereço"),
    ("host", "IP / hostname"),
    ("port", "Porta"),
    ("username", "Usuário / login"),
    ("password", "Senha"),
    ("notes", "Observações / chaves / detalhes"),
)

class PassKey(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassKey • Cofre de acessos")
        self.geometry("1060x640")
        self.minsize(750, 480)
        self.configure(bg="#f7f9fc")
        self.db = None
        self.key = None
        self.rows = []
        self.filtered = []
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        try:
            self.db = Storage()
            if not self.unlock():
                self.destroy()
                return
            self.build()
            self.refresh()
        except Exception as exc:
            messagebox.showerror("Não foi possível abrir o PassKey", str(exc), parent=self)
            self.quit_app()

    def unlock(self):
        cfg = self.db.get_config()
        if cfg is None:
            p1 = simpledialog.askstring("Criar cofre", "Defina uma senha mestra forte (mínimo 12 caracteres):", show="*", parent=self)
            if p1 is None:
                return False
            if len(p1) < 12:
                raise ValueError("A senha mestra deve ter pelo menos 12 caracteres")
            p2 = simpledialog.askstring("Confirmar senha", "Digite novamente a senha mestra:", show="*", parent=self)
            if p1 != p2:
                raise ValueError("As senhas mestras não coincidem")
            salt = os.urandom(16)
            key = derive_key(p1, salt)
            self.db.initialize(salt, encrypt(key, CHECK))
            self.key = key
            return True
        salt, verifier = cfg
        for _ in range(3):
            password = simpledialog.askstring("Desbloquear cofre", "Senha mestra:", show="*", parent=self)
            if password is None:
                return False
            key = derive_key(password, bytes(salt))
            try:
                if decrypt(key, bytes(verifier)) == CHECK:
                    self.key = key
                    return True
            except (InvalidTag, ValueError):
                pass
            messagebox.showerror("Acesso negado", "Senha mestra incorreta.", parent=self)
        return False

    def build(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", rowheight=34, background="#ffffff", foreground="#162337", fieldbackground="#ffffff", borderwidth=0)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#deebff")], foreground=[("selected", "#102c4b")])
        top = tk.Frame(self, bg="#102c4b", padx=24, pady=18)
        top.pack(fill="x")
        tk.Label(top, text="PassKey", font=("Segoe UI", 22, "bold"), fg="#ffffff", bg="#102c4b").pack(side="left")
        tk.Label(top, text="  Cofre criptografado", font=("Segoe UI", 11), fg="#b8d3ed", bg="#102c4b").pack(side="left")
        tools = tk.Frame(self, bg="#f7f9fc", padx=22, pady=18)
        tools.pack(fill="x")
        tk.Label(tools, text="Buscar", bg="#f7f9fc").pack(side="left")
        self.query = tk.StringVar()
        self.query.trace_add("write", lambda *_: self.filter_rows())
        ttk.Entry(tools, textvariable=self.query, width=32).pack(side="left", padx=10)
        ttk.Button(tools, text="+ Novo acesso", command=self.add).pack(side="right", padx=4)
        ttk.Button(tools, text="Editar", command=self.edit).pack(side="right", padx=4)
        ttk.Button(tools, text="Excluir", command=self.remove).pack(side="right", padx=4)
        area = tk.Frame(self, bg="#f7f9fc", padx=22)
        area.pack(fill="both", expand=True)
        self.gridview = ttk.Treeview(area, columns=("title", "category", "user", "host"), show="headings", selectmode="browse")
        for name, title, width in (("title", "Identificação", 280), ("category", "Categoria", 140), ("user", "Usuário", 190), ("host", "Servidor / URL", 250)):
            self.gridview.heading(name, text=title)
            self.gridview.column(name, width=width)
        scroll = ttk.Scrollbar(area, orient="vertical", command=self.gridview.yview)
        self.gridview.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.gridview.pack(side="left", fill="both", expand=True)
        self.gridview.bind("<Double-1>", lambda *_: self.edit())
        footer = tk.Frame(self, bg="#f7f9fc", padx=22, pady=14)
        footer.pack(fill="x")
        ttk.Button(footer, text="Copiar senha", command=self.copy_password).pack(side="right", padx=4)
        ttk.Button(footer, text="Copiar usuário", command=self.copy_user).pack(side="right", padx=4)
        self.status = tk.Label(footer, text="Dados descriptografados somente nesta sessão", bg="#f7f9fc", fg="#62748b")
        self.status.pack(side="left")

    def refresh(self):
        self.rows = [(int(i), decrypt_record(self.key, bytes(payload))) for i, payload in self.db.entries()]
        self.filter_rows()

    def filter_rows(self):
        needle = self.query.get().casefold()
        self.filtered = [(i, obj) for i, obj in self.rows if needle in " ".join(str(obj.get(field, "")) for field in ("title", "category", "url", "host", "username")).casefold()]
        for iid in self.gridview.get_children():
            self.gridview.delete(iid)
        for i, obj in self.filtered:
            self.gridview.insert("", "end", iid=str(i), values=(obj.get("title", ""), obj.get("category", ""), obj.get("username", ""), obj.get("host") or obj.get("url", "")))
        self.status.configure(text=f"{len(self.filtered)} acesso(s) • dados protegidos com AES-256-GCM")

    def selected(self):
        selection = self.gridview.selection()
        if not selection:
            messagebox.showinfo("Selecione um acesso", "Selecione um registro primeiro.", parent=self)
            return None
        number = int(selection[0])
        return next(((i, data) for i, data in self.rows if i == number), None)

    def editor(self, value=None):
        window = tk.Toplevel(self)
        window.title("Editar acesso" if value else "Novo acesso")
        window.geometry("630x620")
        window.minsize(520, 520)
        window.transient(self)
        window.grab_set()
        form = tk.Frame(window, padx=22, pady=18)
        form.pack(fill="both", expand=True)
        variables = {}
        for index, (field, label) in enumerate(FIELDS):
            tk.Label(form, text=label, anchor="w").grid(row=index, column=0, sticky="w", pady=10)
            if field == "notes":
                widget = tk.Text(form, width=44, height=5, wrap="word")
                widget.insert("1.0", (value or {}).get(field, ""))
            else:
                var = tk.StringVar(value=(value or {}).get(field, ""))
                widget = ttk.Entry(form, width=46, textvariable=var, show="*" if field == "password" else "")
                variables[field] = var
            widget.grid(row=index, column=1, sticky="ew", padx=(14, 0))
            if field == "notes":
                notes = widget
        form.columnconfigure(1, weight=1)
        result = {}
        def save():
            record = {k: v.get().strip() for k, v in variables.items()}
            record["notes"] = notes.get("1.0", "end-1c")
            if not record["title"]:
                messagebox.showwarning("Campo obrigatório", "Informe o nome / identificação.", parent=window)
                return
            result.update(record)
            window.destroy()
        ttk.Button(form, text="Salvar acesso", command=save).grid(row=len(FIELDS), column=1, sticky="e", pady=22)
        window.wait_window()
        return result if result else None

    def add(self):
        value = self.editor()
        if value:
            self.action(lambda: self.db.add(encrypt_record(self.key, value)))

    def edit(self):
        selection = self.selected()
        if selection:
            i, old = selection
            value = self.editor(old)
            if value:
                self.action(lambda: self.db.update(i, encrypt_record(self.key, value)))

    def remove(self):
        selection = self.selected()
        if selection and messagebox.askyesno("Excluir acesso", "Excluir este acesso permanentemente?", parent=self):
            self.action(lambda: self.db.delete(selection[0]))

    def action(self, fn):
        try:
            fn()
            self.refresh()
        except Exception as exc:
            messagebox.showerror("Erro no banco", str(exc), parent=self)

    def copy(self, field):
        selection = self.selected()
        if not selection:
            return
        value = selection[1].get(field, "")
        if not value:
            messagebox.showinfo("Campo vazio", "Este campo não foi preenchido.", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()
        messagebox.showinfo("Copiado", "Copiado para a área de transferência. Limpe-a após usar.", parent=self)

    def copy_password(self):
        self.copy("password")

    def copy_user(self):
        self.copy("username")

    def quit_app(self):
        self.key = None
        if self.db:
            try:
                self.db.close()
            except Exception:
                pass
        self.destroy()

if __name__ == "__main__":
    PassKey().mainloop()
