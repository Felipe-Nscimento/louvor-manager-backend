from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
import psycopg2
import psycopg2.extras
import os
import hashlib
import secrets
import urllib.request
import urllib.parse
import json

app = FastAPI(title="Praizy API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL")
EVOLUTION_API_URL = os.environ.get("EVOLUTION_API_URL", "")
EVOLUTION_API_KEY = os.environ.get("EVOLUTION_API_KEY", "")
EVOLUTION_INSTANCE = os.environ.get("EVOLUTION_INSTANCE", "")

security = HTTPBearer(auto_error=False)

NIVEIS = ["lider", "gestor", "ministro", "voluntario"]
PODE_CRIAR_ESCALA  = ["lider", "gestor"]
PODE_EDITAR_ESCALA = ["lider", "gestor", "ministro"]
PODE_GERENCIAR_MEMBROS = ["lider", "gestor"]


def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def hash_senha(s): return hashlib.sha256(s.encode()).hexdigest()
def gerar_token(): return secrets.token_hex(32)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS integrantes (
            id          SERIAL PRIMARY KEY,
            nome        TEXT NOT NULL,
            email       TEXT NOT NULL UNIQUE,
            senha_hash  TEXT NOT NULL,
            whatsapp    TEXT,
            nivel       TEXT NOT NULL DEFAULT 'voluntario',
            foto        TEXT,
            criado_em   TIMESTAMP DEFAULT NOW()
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
    # Garante que se ja existia tabela antiga, adiciona colunas novas
    for col, tipo in [("whatsapp","TEXT"),("nivel","TEXT DEFAULT 'voluntario'"),("foto","TEXT")]:
        try:
            cur.execute(f"ALTER TABLE integrantes ADD COLUMN IF NOT EXISTS {col} {tipo};")
        except Exception:
            conn.rollback()
    conn.commit()
    cur.close(); conn.close()


init_db()


# ── WHATSAPP ────────────────────────────────────────────────────
def enviar_whatsapp(numero: str, mensagem: str):
    if not EVOLUTION_API_URL or not EVOLUTION_API_KEY or not EVOLUTION_INSTANCE:
        return False
    try:
        # Remove tudo que não é dígito e garante código do país
        n = ''.join(filter(str.isdigit, numero))
        if len(n) == 11: n = '55' + n
        if len(n) == 10: n = '55' + n
        payload = json.dumps({"number": n, "text": mensagem}).encode()
        url = f"{EVOLUTION_API_URL}/message/sendText/{EVOLUTION_INSTANCE}"
        req = urllib.request.Request(url, data=payload,
              headers={"Content-Type":"application/json","apikey":EVOLUTION_API_KEY},
              method="POST")
        urllib.request.urlopen(req, timeout=8)
        return True
    except Exception:
        return False


def notificar_escalado(integrante_id: int, data_evento: str, evento: str, funcao: str):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT nome, whatsapp FROM integrantes WHERE id=%s", (integrante_id,))
        row = cur.fetchone()
        cur.close(); conn.close()
        if not row or not row["whatsapp"]:
            return
        nome_primeiro = row["nome"].split()[0]
        evento_str = f" — {evento}" if evento else ""
        msg = (
            f"🎵 *Praizy* — Você foi escalado!\n\n"
            f"Olá, *{nome_primeiro}*! Você está na escala:\n\n"
            f"📅 *Data:* {data_evento}{evento_str}\n"
            f"🎸 *Função:* {funcao}\n\n"
            f"Acesse o Praizy para mais detalhes."
        )
        enviar_whatsapp(row["whatsapp"], msg)
    except Exception:
        pass


# ── AUTH ────────────────────────────────────────────────────────
def get_integrante_atual(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(401, "Token não fornecido")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT i.id, i.nome, i.email, i.nivel, i.whatsapp, i.foto
        FROM sessoes s
        JOIN integrantes i ON i.id = s.integrante_id
        WHERE s.token = %s
    """, (credentials.credentials,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        raise HTTPException(401, "Sessão inválida ou expirada")
    return dict(row)

def requer_nivel(niveis_permitidos: list):
    def check(atual=Depends(get_integrante_atual)):
        if atual["nivel"] not in niveis_permitidos:
            raise HTTPException(403, "Você não tem permissão para esta ação")
        return atual
    return check


# ── MODELS ─────────────────────────────────────────────────────
class LoginData(BaseModel):
    email: str
    senha: str

class IntegranteCriar(BaseModel):
    nome: str
    email: str
    senha: str
    whatsapp: Optional[str] = None
    nivel: str = "voluntario"
    funcoes: List[str] = []
    foto: Optional[str] = None

class IntegranteEditar(BaseModel):
    nome: str
    email: str
    senha: Optional[str] = None
    whatsapp: Optional[str] = None
    nivel: str
    funcoes: List[str] = []
    foto: Optional[str] = None

class EscalaSlotIn(BaseModel):
    integrante_id: int
    funcao: str

class EscalaCriar(BaseModel):
    data: str
    evento: Optional[str] = ""
    slots: List[EscalaSlotIn]

class EscalaEditar(BaseModel):
    data: str
    evento: Optional[str] = ""
    slots: List[EscalaSlotIn]


# ── AUTH ENDPOINTS ──────────────────────────────────────────────
@app.post("/auth/login")
def login(data: LoginData):
    if not data.email or not data.senha:
        raise HTTPException(400, "E-mail e senha são obrigatórios")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, nome, email, nivel, whatsapp, foto FROM integrantes WHERE email=%s AND senha_hash=%s",
        (data.email.lower().strip(), hash_senha(data.senha))
    )
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        raise HTTPException(401, "E-mail ou senha incorretos")
    token = gerar_token()
    cur.execute("INSERT INTO sessoes (integrante_id, token) VALUES (%s,%s)", (row["id"], token))
    conn.commit()
    cur.close(); conn.close()
    return {"token": token, "integrante": dict(row)}

@app.post("/auth/logout", status_code=204)
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials: return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM sessoes WHERE token=%s", (credentials.credentials,))
    conn.commit()
    cur.close(); conn.close()

@app.get("/auth/me")
def me(atual=Depends(get_integrante_atual)):
    return atual


# ── INTEGRANTES ─────────────────────────────────────────────────
@app.get("/integrantes")
def listar_integrantes(atual=Depends(get_integrante_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, nome, email, whatsapp, nivel, foto FROM integrantes ORDER BY nome")
    rows = cur.fetchall()
    result = []
    for r in rows:
        cur.execute("SELECT nome FROM funcoes_integrante WHERE integrante_id=%s", (r["id"],))
        funcoes = [x["nome"] for x in cur.fetchall()]
        d = dict(r); d["funcoes"] = funcoes; result.append(d)
    cur.close(); conn.close()
    return result

@app.post("/integrantes", status_code=201)
def criar_integrante(data: IntegranteCriar, atual=Depends(requer_nivel(PODE_GERENCIAR_MEMBROS))):
    if not data.nome.strip(): raise HTTPException(400, "Nome é obrigatório")
    if not data.email.strip() or "@" not in data.email: raise HTTPException(400, "E-mail inválido")
    if not data.senha or len(data.senha) < 6: raise HTTPException(400, "Senha deve ter ao menos 6 caracteres")
    if data.nivel not in NIVEIS: raise HTTPException(400, "Nível inválido")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE email=%s", (data.email.lower().strip(),))
    if cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(400, "E-mail já cadastrado")
    cur.execute(
        "INSERT INTO integrantes (nome, email, senha_hash, whatsapp, nivel, foto) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
        (data.nome.strip(), data.email.lower().strip(), hash_senha(data.senha), data.whatsapp, data.nivel, data.foto)
    )
    iid = cur.fetchone()["id"]
    for f in data.funcoes:
        cur.execute("INSERT INTO funcoes_integrante (integrante_id, nome) VALUES (%s,%s)", (iid, f.strip()))
    conn.commit()
    cur.close(); conn.close()
    return {"id": iid, "nome": data.nome, "nivel": data.nivel, "funcoes": data.funcoes}

@app.put("/integrantes/{iid}")
def editar_integrante(iid: int, data: IntegranteEditar, atual=Depends(requer_nivel(PODE_GERENCIAR_MEMBROS))):
    if not data.nome.strip(): raise HTTPException(400, "Nome é obrigatório")
    if data.nivel not in NIVEIS: raise HTTPException(400, "Nível inválido")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE id=%s", (iid,))
    if not cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(404, "Integrante não encontrado")
    if data.senha and len(data.senha) >= 6:
        cur.execute(
            "UPDATE integrantes SET nome=%s,email=%s,senha_hash=%s,whatsapp=%s,nivel=%s,foto=%s WHERE id=%s",
            (data.nome.strip(), data.email.lower().strip(), hash_senha(data.senha), data.whatsapp, data.nivel,
             data.foto if data.foto is not None else None, iid)
        )
    else:
        cur.execute(
            "UPDATE integrantes SET nome=%s,email=%s,whatsapp=%s,nivel=%s,foto=%s WHERE id=%s",
            (data.nome.strip(), data.email.lower().strip(), data.whatsapp, data.nivel,
             data.foto if data.foto is not None else None, iid)
        )
    cur.execute("DELETE FROM funcoes_integrante WHERE integrante_id=%s", (iid,))
    for f in data.funcoes:
        cur.execute("INSERT INTO funcoes_integrante (integrante_id, nome) VALUES (%s,%s)", (iid, f.strip()))
    conn.commit()
    cur.close(); conn.close()
    return {"id": iid, "nome": data.nome, "nivel": data.nivel}

@app.delete("/integrantes/{iid}", status_code=204)
def deletar_integrante(iid: int, atual=Depends(requer_nivel(PODE_GERENCIAR_MEMBROS))):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM integrantes WHERE id=%s", (iid,))
    if cur.rowcount == 0:
        cur.close(); conn.close()
        raise HTTPException(404, "Integrante não encontrado")
    conn.commit()
    cur.close(); conn.close()


# ── ESCALAS ─────────────────────────────────────────────────────
def _escala_com_slots(cur, escala_id):
    cur.execute("""
        SELECT es.id as slot_id, es.funcao,
               i.id as integrante_id, i.nome as integrante_nome, i.foto as integrante_foto
        FROM escala_slots es
        LEFT JOIN integrantes i ON i.id = es.integrante_id
        WHERE es.escala_id=%s
    """, (escala_id,))
    return [dict(r) for r in cur.fetchall()]

@app.get("/escalas")
def listar_escalas(atual=Depends(get_integrante_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, data::text, evento FROM escalas ORDER BY data DESC")
    escalas = cur.fetchall()
    result = []
    for e in escalas:
        slots = _escala_com_slots(cur, e["id"])
        result.append({"id":e["id"],"data":e["data"],"evento":e["evento"],"slots":slots})
    cur.close(); conn.close()
    return result

@app.post("/escalas", status_code=201)
def criar_escala(data: EscalaCriar, atual=Depends(requer_nivel(PODE_CRIAR_ESCALA))):
    if not data.data: raise HTTPException(400, "Data é obrigatória")
    if not data.slots: raise HTTPException(400, "Escale ao menos um integrante")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO escalas (data, evento) VALUES (%s,%s) RETURNING id", (data.data, data.evento))
    eid = cur.fetchone()["id"]
    for slot in data.slots:
        cur.execute("INSERT INTO escala_slots (escala_id,integrante_id,funcao) VALUES (%s,%s,%s)",
                    (eid, slot.integrante_id, slot.funcao))
    conn.commit()
    cur.close(); conn.close()
    # Notificar WhatsApp em background
    for slot in data.slots:
        notificar_escalado(slot.integrante_id, data.data, data.evento or "", slot.funcao)
    return {"id": eid}

@app.put("/escalas/{eid}")
def editar_escala(eid: int, data: EscalaEditar, atual=Depends(requer_nivel(PODE_EDITAR_ESCALA))):
    if not data.data: raise HTTPException(400, "Data é obrigatória")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM escalas WHERE id=%s", (eid,))
    if not cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(404, "Escala não encontrada")
    cur.execute("UPDATE escalas SET data=%s, evento=%s WHERE id=%s", (data.data, data.evento, eid))
    cur.execute("DELETE FROM escala_slots WHERE escala_id=%s", (eid,))
    for slot in data.slots:
        cur.execute("INSERT INTO escala_slots (escala_id,integrante_id,funcao) VALUES (%s,%s,%s)",
                    (eid, slot.integrante_id, slot.funcao))
    conn.commit()
    cur.close(); conn.close()
    for slot in data.slots:
        notificar_escalado(slot.integrante_id, data.data, data.evento or "", slot.funcao)
    return {"id": eid}

@app.delete("/escalas/{eid}", status_code=204)
def deletar_escala(eid: int, atual=Depends(requer_nivel(PODE_CRIAR_ESCALA))):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM escalas WHERE id=%s", (eid,))
    if cur.rowcount == 0:
        cur.close(); conn.close()
        raise HTTPException(404, "Escala não encontrada")
    conn.commit()
    cur.close(); conn.close()


# ── SUBSTITUIÇÕES ───────────────────────────────────────────────
@app.get("/substitutos/{iid}")
def substitutos(iid: int, atual=Depends(get_integrante_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT nome FROM funcoes_integrante WHERE integrante_id=%s", (iid,))
    funcoes = [r["nome"] for r in cur.fetchall()]
    result = []
    for f in funcoes:
        cur.execute("""
            SELECT i.id, i.nome FROM integrantes i
            JOIN funcoes_integrante fi ON fi.integrante_id = i.id
            WHERE fi.nome=%s AND i.id!=%s
        """, (f, iid))
        result.append({"funcao": f, "substitutos": [dict(r) for r in cur.fetchall()]})
    cur.close(); conn.close()
    return result

@app.get("/health")
def health():
    return {"status": "ok"}
