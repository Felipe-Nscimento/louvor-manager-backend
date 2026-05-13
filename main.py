from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
import psycopg2
import psycopg2.extras
import os, hashlib, secrets, json, urllib.request

app = FastAPI(title="Praizy API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DATABASE_URL    = os.environ.get("DATABASE_URL")
SUPER_ADMIN_KEY = os.environ.get("SUPER_ADMIN_KEY", "praizy-super-secret")
EVOLUTION_API_URL  = os.environ.get("EVOLUTION_API_URL", "")
EVOLUTION_API_KEY  = os.environ.get("EVOLUTION_API_KEY", "")
EVOLUTION_INSTANCE = os.environ.get("EVOLUTION_INSTANCE", "")

security = HTTPBearer(auto_error=False)
NIVEIS = ["gestor","ministro","voluntario"]
PODE_CRIAR_ESCALA   = ["gestor"]
PODE_EDITAR_ESCALA  = ["gestor","ministro"]
PODE_GERENCIAR_INT  = ["gestor"]


def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def hash_senha(s): return hashlib.sha256(s.encode()).hexdigest()
def gerar_token(): return secrets.token_hex(32)


def init_db():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS igrejas (
            id          SERIAL PRIMARY KEY,
            nome        TEXT NOT NULL,
            endereco    TEXT,
            logo        TEXT,
            status      TEXT NOT NULL DEFAULT 'pendente',
            criado_em   TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS integrantes (
            id          SERIAL PRIMARY KEY,
            igreja_id   INTEGER REFERENCES igrejas(id) ON DELETE CASCADE,
            nome        TEXT NOT NULL,
            email       TEXT NOT NULL,
            senha_hash  TEXT NOT NULL,
            whatsapp    TEXT,
            nivel       TEXT NOT NULL DEFAULT 'voluntario',
            foto        TEXT,
            criado_em   TIMESTAMP DEFAULT NOW(),
            UNIQUE(email, igreja_id)
        );
        CREATE TABLE IF NOT EXISTS funcoes_integrante (
            id              SERIAL PRIMARY KEY,
            integrante_id   INTEGER REFERENCES integrantes(id) ON DELETE CASCADE,
            nome            TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessoes (
            id              SERIAL PRIMARY KEY,
            integrante_id   INTEGER REFERENCES integrantes(id) ON DELETE CASCADE,
            token           TEXT NOT NULL UNIQUE,
            criado_em       TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS escalas (
            id          SERIAL PRIMARY KEY,
            igreja_id   INTEGER REFERENCES igrejas(id) ON DELETE CASCADE,
            data        DATE NOT NULL,
            evento      TEXT,
            criado_em   TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS escala_slots (
            id              SERIAL PRIMARY KEY,
            escala_id       INTEGER REFERENCES escalas(id) ON DELETE CASCADE,
            integrante_id   INTEGER REFERENCES integrantes(id) ON DELETE SET NULL,
            funcao          TEXT NOT NULL
        );
    """)
    # migrações seguras
    for sql in [
        "ALTER TABLE igrejas ADD COLUMN IF NOT EXISTS logo TEXT",
        "ALTER TABLE igrejas ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pendente'",
        "ALTER TABLE integrantes ADD COLUMN IF NOT EXISTS igreja_id INTEGER",
        "ALTER TABLE integrantes ADD COLUMN IF NOT EXISTS whatsapp TEXT",
        "ALTER TABLE integrantes ADD COLUMN IF NOT EXISTS foto TEXT",
        "ALTER TABLE escalas ADD COLUMN IF NOT EXISTS igreja_id INTEGER",
    ]:
        try: cur.execute(sql)
        except: conn.rollback()
    conn.commit(); cur.close(); conn.close()

init_db()


# ── WHATSAPP ────────────────────────────────────────────────────
def enviar_whatsapp(numero: str, mensagem: str):
    if not EVOLUTION_API_URL: return
    try:
        n = ''.join(filter(str.isdigit, numero))
        if len(n) == 11: n = '55' + n
        payload = json.dumps({"number": n, "text": mensagem}).encode()
        url = f"{EVOLUTION_API_URL}/message/sendText/{EVOLUTION_INSTANCE}"
        req = urllib.request.Request(url, data=payload,
            headers={"Content-Type":"application/json","apikey":EVOLUTION_API_KEY}, method="POST")
        urllib.request.urlopen(req, timeout=8)
    except: pass

def notificar_escalado(integrante_id: int, data_str: str, evento: str, funcao: str):
    try:
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT nome, whatsapp FROM integrantes WHERE id=%s", (integrante_id,))
        row = cur.fetchone(); cur.close(); conn.close()
        if not row or not row["whatsapp"]: return
        nome = row["nome"].split()[0]
        ev = f" — {evento}" if evento else ""
        msg = f"🎵 *Praizy* — Você foi escalado!\n\nOlá, *{nome}*!\n\n📅 *Data:* {data_str}{ev}\n🎸 *Função:* {funcao}\n\nAcesse o Praizy para mais detalhes."
        enviar_whatsapp(row["whatsapp"], msg)
    except: pass


# ── AUTH ────────────────────────────────────────────────────────
def get_atual(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials: raise HTTPException(401, "Token não fornecido")
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT i.id, i.nome, i.email, i.nivel, i.whatsapp, i.foto, i.igreja_id,
               ig.nome as igreja_nome, ig.status as igreja_status
        FROM sessoes s
        JOIN integrantes i ON i.id = s.integrante_id
        JOIN igrejas ig ON ig.id = i.igreja_id
        WHERE s.token = %s
    """, (credentials.credentials,))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row: raise HTTPException(401, "Sessão inválida")
    if row["igreja_status"] != "ativa": raise HTTPException(403, "Igreja ainda não aprovada")
    return dict(row)

def requer_nivel(niveis):
    def check(atual=Depends(get_atual)):
        if atual["nivel"] not in niveis:
            raise HTTPException(403, "Sem permissão para esta ação")
        return atual
    return check


# ── MODELS ─────────────────────────────────────────────────────
class SolicitacaoCadastro(BaseModel):
    igreja_nome: str
    igreja_endereco: Optional[str] = None
    igreja_logo: Optional[str] = None
    gestor_nome: str
    gestor_email: str
    gestor_senha: str

class LoginData(BaseModel):
    email: str
    senha: str

class IntegranteCriar(BaseModel):
    nome: str; email: str; senha: str
    whatsapp: Optional[str] = None
    nivel: str = "voluntario"
    funcoes: List[str] = []
    foto: Optional[str] = None

class IntegranteEditar(BaseModel):
    nome: str; email: str
    senha: Optional[str] = None
    whatsapp: Optional[str] = None
    nivel: str
    funcoes: List[str] = []
    foto: Optional[str] = None

class EscalaSlotIn(BaseModel):
    integrante_id: int; funcao: str

class EscalaDados(BaseModel):
    data: str
    evento: Optional[str] = ""
    slots: List[EscalaSlotIn]

class IgrejaEditar(BaseModel):
    nome: str
    endereco: Optional[str] = None
    logo: Optional[str] = None


# ── CADASTRO PÚBLICO (solicitar) ────────────────────────────────
@app.post("/cadastro/solicitar", status_code=201)
def solicitar_cadastro(data: SolicitacaoCadastro):
    if not data.igreja_nome.strip(): raise HTTPException(400, "Nome da igreja é obrigatório")
    if not data.gestor_nome.strip(): raise HTTPException(400, "Nome do gestor é obrigatório")
    if not data.gestor_email or "@" not in data.gestor_email: raise HTTPException(400, "E-mail inválido")
    if not data.gestor_senha or len(data.gestor_senha) < 6: raise HTTPException(400, "Senha deve ter ao menos 6 caracteres")
    conn = get_conn(); cur = conn.cursor()
    # verifica e-mail único global
    cur.execute("SELECT id FROM integrantes WHERE email=%s", (data.gestor_email.lower().strip(),))
    if cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(400, "E-mail já cadastrado")
    # cria igreja com status pendente
    cur.execute(
        "INSERT INTO igrejas (nome, endereco, logo, status) VALUES (%s,%s,%s,'pendente') RETURNING id",
        (data.igreja_nome.strip(), data.igreja_endereco, data.igreja_logo)
    )
    igreja_id = cur.fetchone()["id"]
    # cria gestor vinculado
    cur.execute(
        "INSERT INTO integrantes (igreja_id,nome,email,senha_hash,nivel) VALUES (%s,%s,%s,%s,'gestor') RETURNING id",
        (igreja_id, data.gestor_nome.strip(), data.gestor_email.lower().strip(), hash_senha(data.gestor_senha))
    )
    conn.commit(); cur.close(); conn.close()
    return {"mensagem": "Solicitação enviada! Aguarde a aprovação do administrador."}


# ── SUPER ADMIN ─────────────────────────────────────────────────
def check_super(key: str):
    if key != SUPER_ADMIN_KEY: raise HTTPException(403, "Chave de admin inválida")

@app.get("/admin/igrejas")
def admin_listar(key: str):
    check_super(key)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT ig.*, i.nome as gestor_nome, i.email as gestor_email
        FROM igrejas ig
        LEFT JOIN integrantes i ON i.igreja_id=ig.id AND i.nivel='gestor'
        ORDER BY ig.criado_em DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    cur.close(); conn.close()
    return rows

@app.post("/admin/igrejas/{igreja_id}/aprovar")
def admin_aprovar(igreja_id: int, key: str):
    check_super(key)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("UPDATE igrejas SET status='ativa' WHERE id=%s", (igreja_id,))
    if cur.rowcount == 0: raise HTTPException(404, "Igreja não encontrada")
    conn.commit(); cur.close(); conn.close()
    return {"mensagem": "Igreja aprovada com sucesso!"}

@app.post("/admin/igrejas/{igreja_id}/rejeitar")
def admin_rejeitar(igreja_id: int, key: str):
    check_super(key)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("UPDATE igrejas SET status='rejeitada' WHERE id=%s", (igreja_id,))
    conn.commit(); cur.close(); conn.close()
    return {"mensagem": "Igreja rejeitada."}

@app.delete("/admin/igrejas/{igreja_id}")
def admin_deletar(igreja_id: int, key: str):
    check_super(key)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM igrejas WHERE id=%s", (igreja_id,))
    conn.commit(); cur.close(); conn.close()
    return {"mensagem": "Igreja removida."}


# ── AUTH ENDPOINTS ──────────────────────────────────────────────
@app.post("/auth/login")
def login(data: LoginData):
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "SELECT id,nome,email,nivel,whatsapp,foto,igreja_id FROM integrantes WHERE email=%s AND senha_hash=%s",
        (data.email.lower().strip(), hash_senha(data.senha))
    )
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        raise HTTPException(401, "E-mail ou senha incorretos")
    cur.execute("SELECT status, nome FROM igrejas WHERE id=%s", (row["igreja_id"],))
    ig = cur.fetchone()
    if ig["status"] == "pendente":
        cur.close(); conn.close()
        raise HTTPException(403, f"A igreja '{ig['nome']}' ainda aguarda aprovação.")
    if ig["status"] == "rejeitada":
        cur.close(); conn.close()
        raise HTTPException(403, f"O cadastro da igreja '{ig['nome']}' foi rejeitado.")
    token = gerar_token()
    cur.execute("INSERT INTO sessoes (integrante_id,token) VALUES (%s,%s)", (row["id"], token))
    conn.commit(); cur.close(); conn.close()
    return {"token": token, "integrante": dict(row), "igreja": {"nome": ig["nome"], "status": ig["status"]}}

@app.post("/auth/logout", status_code=204)
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials: return
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM sessoes WHERE token=%s", (credentials.credentials,))
    conn.commit(); cur.close(); conn.close()

@app.get("/auth/me")
def me(atual=Depends(get_atual)):
    return atual


# ── MINHA IGREJA ────────────────────────────────────────────────
@app.get("/minha-igreja")
def minha_igreja(atual=Depends(get_atual)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id,nome,endereco,logo,status FROM igrejas WHERE id=%s", (atual["igreja_id"],))
    row = cur.fetchone(); cur.close(); conn.close()
    return dict(row)

@app.put("/minha-igreja")
def editar_minha_igreja(data: IgrejaEditar, atual=Depends(requer_nivel(["gestor"]))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("UPDATE igrejas SET nome=%s,endereco=%s,logo=%s WHERE id=%s",
                (data.nome, data.endereco, data.logo, atual["igreja_id"]))
    conn.commit(); cur.close(); conn.close()
    return {"mensagem": "Igreja atualizada"}


# ── INTEGRANTES ─────────────────────────────────────────────────
@app.get("/integrantes")
def listar_integrantes(atual=Depends(get_atual)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id,nome,email,whatsapp,nivel,foto FROM integrantes WHERE igreja_id=%s ORDER BY nome", (atual["igreja_id"],))
    rows = cur.fetchall(); result = []
    for r in rows:
        cur.execute("SELECT nome FROM funcoes_integrante WHERE integrante_id=%s", (r["id"],))
        d = dict(r); d["funcoes"] = [x["nome"] for x in cur.fetchall()]; result.append(d)
    cur.close(); conn.close(); return result

@app.post("/integrantes", status_code=201)
def criar_integrante(data: IntegranteCriar, atual=Depends(requer_nivel(PODE_GERENCIAR_INT))):
    if not data.nome.strip(): raise HTTPException(400, "Nome obrigatório")
    if not data.email or "@" not in data.email: raise HTTPException(400, "E-mail inválido")
    if not data.senha or len(data.senha) < 6: raise HTTPException(400, "Senha mínimo 6 caracteres")
    if data.nivel not in NIVEIS: raise HTTPException(400, "Nível inválido")
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE email=%s", (data.email.lower().strip(),))
    if cur.fetchone():
        cur.close(); conn.close(); raise HTTPException(400, "E-mail já cadastrado")
    cur.execute(
        "INSERT INTO integrantes (igreja_id,nome,email,senha_hash,whatsapp,nivel,foto) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (atual["igreja_id"], data.nome.strip(), data.email.lower().strip(), hash_senha(data.senha), data.whatsapp, data.nivel, data.foto)
    )
    iid = cur.fetchone()["id"]
    for f in data.funcoes:
        cur.execute("INSERT INTO funcoes_integrante (integrante_id,nome) VALUES (%s,%s)", (iid, f.strip()))
    conn.commit(); cur.close(); conn.close()
    return {"id": iid}

@app.put("/integrantes/{iid}")
def editar_integrante(iid: int, data: IntegranteEditar, atual=Depends(requer_nivel(PODE_GERENCIAR_INT))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE id=%s AND igreja_id=%s", (iid, atual["igreja_id"]))
    if not cur.fetchone():
        cur.close(); conn.close(); raise HTTPException(404, "Integrante não encontrado")
    if data.senha and len(data.senha) >= 6:
        cur.execute("UPDATE integrantes SET nome=%s,email=%s,senha_hash=%s,whatsapp=%s,nivel=%s,foto=%s WHERE id=%s",
                    (data.nome.strip(), data.email.lower().strip(), hash_senha(data.senha), data.whatsapp, data.nivel, data.foto, iid))
    else:
        cur.execute("UPDATE integrantes SET nome=%s,email=%s,whatsapp=%s,nivel=%s,foto=%s WHERE id=%s",
                    (data.nome.strip(), data.email.lower().strip(), data.whatsapp, data.nivel, data.foto, iid))
    cur.execute("DELETE FROM funcoes_integrante WHERE integrante_id=%s", (iid,))
    for f in data.funcoes:
        cur.execute("INSERT INTO funcoes_integrante (integrante_id,nome) VALUES (%s,%s)", (iid, f.strip()))
    conn.commit(); cur.close(); conn.close()
    return {"id": iid}

@app.delete("/integrantes/{iid}", status_code=204)
def deletar_integrante(iid: int, atual=Depends(requer_nivel(PODE_GERENCIAR_INT))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM integrantes WHERE id=%s AND igreja_id=%s", (iid, atual["igreja_id"]))
    if cur.rowcount == 0:
        cur.close(); conn.close(); raise HTTPException(404, "Não encontrado")
    conn.commit(); cur.close(); conn.close()


# ── ESCALAS ─────────────────────────────────────────────────────
@app.get("/escalas")
def listar_escalas(atual=Depends(get_atual)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id,data::text,evento FROM escalas WHERE igreja_id=%s ORDER BY data DESC", (atual["igreja_id"],))
    escalas = cur.fetchall(); result = []
    for e in escalas:
        cur.execute("""
            SELECT es.funcao, i.id as integrante_id, i.nome as integrante_nome, i.foto as integrante_foto
            FROM escala_slots es LEFT JOIN integrantes i ON i.id=es.integrante_id
            WHERE es.escala_id=%s
        """, (e["id"],))
        result.append({"id":e["id"],"data":e["data"],"evento":e["evento"],"slots":[dict(s) for s in cur.fetchall()]})
    cur.close(); conn.close(); return result

@app.post("/escalas", status_code=201)
def criar_escala(data: EscalaDados, atual=Depends(requer_nivel(PODE_CRIAR_ESCALA))):
    if not data.data: raise HTTPException(400, "Data obrigatória")
    if not data.slots: raise HTTPException(400, "Escale ao menos um integrante")
    conn = get_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO escalas (igreja_id,data,evento) VALUES (%s,%s,%s) RETURNING id",
                (atual["igreja_id"], data.data, data.evento))
    eid = cur.fetchone()["id"]
    for s in data.slots:
        cur.execute("INSERT INTO escala_slots (escala_id,integrante_id,funcao) VALUES (%s,%s,%s)", (eid,s.integrante_id,s.funcao))
    conn.commit(); cur.close(); conn.close()
    for s in data.slots:
        notificar_escalado(s.integrante_id, data.data, data.evento or "", s.funcao)
    return {"id": eid}

@app.put("/escalas/{eid}")
def editar_escala(eid: int, data: EscalaDados, atual=Depends(requer_nivel(PODE_EDITAR_ESCALA))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM escalas WHERE id=%s AND igreja_id=%s", (eid, atual["igreja_id"]))
    if not cur.fetchone():
        cur.close(); conn.close(); raise HTTPException(404, "Escala não encontrada")
    cur.execute("UPDATE escalas SET data=%s,evento=%s WHERE id=%s", (data.data, data.evento, eid))
    cur.execute("DELETE FROM escala_slots WHERE escala_id=%s", (eid,))
    for s in data.slots:
        cur.execute("INSERT INTO escala_slots (escala_id,integrante_id,funcao) VALUES (%s,%s,%s)", (eid,s.integrante_id,s.funcao))
    conn.commit(); cur.close(); conn.close()
    for s in data.slots:
        notificar_escalado(s.integrante_id, data.data, data.evento or "", s.funcao)
    return {"id": eid}

@app.delete("/escalas/{eid}", status_code=204)
def deletar_escala(eid: int, atual=Depends(requer_nivel(PODE_CRIAR_ESCALA))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM escalas WHERE id=%s AND igreja_id=%s", (eid, atual["igreja_id"]))
    if cur.rowcount == 0:
        cur.close(); conn.close(); raise HTTPException(404, "Não encontrada")
    conn.commit(); cur.close(); conn.close()


# ── SUBSTITUIÇÕES ───────────────────────────────────────────────
@app.get("/substitutos/{iid}")
def substitutos(iid: int, atual=Depends(get_atual)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE id=%s AND igreja_id=%s", (iid, atual["igreja_id"]))
    if not cur.fetchone():
        cur.close(); conn.close(); raise HTTPException(404, "Não encontrado")
    cur.execute("SELECT nome FROM funcoes_integrante WHERE integrante_id=%s", (iid,))
    funcoes = [r["nome"] for r in cur.fetchall()]; result = []
    for f in funcoes:
        cur.execute("""
            SELECT i.id,i.nome FROM integrantes i
            JOIN funcoes_integrante fi ON fi.integrante_id=i.id
            WHERE fi.nome=%s AND i.id!=%s AND i.igreja_id=%s
        """, (f, iid, atual["igreja_id"]))
        result.append({"funcao":f,"substitutos":[dict(r) for r in cur.fetchall()]})
    cur.close(); conn.close(); return result

@app.get("/health")
def health(): return {"status":"ok"}