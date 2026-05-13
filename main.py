from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator, model_validator
from typing import List, Optional
import psycopg2, psycopg2.extras
import os, json, urllib.request, re
import bcrypt
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone

# ── CONFIG ──────────────────────────────────────────────────────
DATABASE_URL       = os.environ.get("DATABASE_URL")
JWT_SECRET         = os.environ.get("JWT_SECRET", "mude-isso-em-producao-agora")
JWT_ALGORITHM      = "HS256"
JWT_EXPIRE_HOURS   = 24 * 7          # 7 dias
FRONTEND_URL       = os.environ.get("FRONTEND_URL", "")  # ex: https://banda-manager-frontend.vercel.app
SUPER_ADMIN_KEY    = os.environ.get("SUPER_ADMIN_KEY", "")
EVOLUTION_API_URL  = os.environ.get("EVOLUTION_API_URL", "")
EVOLUTION_API_KEY  = os.environ.get("EVOLUTION_API_KEY", "")
EVOLUTION_INSTANCE = os.environ.get("EVOLUTION_INSTANCE", "")

# CORS — aceita o domínio do frontend ou tudo em dev
ALLOWED_ORIGINS = [o.strip() for o in FRONTEND_URL.split(",") if o.strip()] if FRONTEND_URL else ["*"]

app = FastAPI(title="Praizy API", docs_url="/docs", redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],
    allow_headers=["Authorization","Content-Type"],
)

security = HTTPBearer(auto_error=False)

NIVEIS             = ["gestor", "ministro", "voluntario"]
PODE_CRIAR_ESCALA  = ["gestor"]
PODE_EDITAR_ESCALA = ["gestor", "ministro"]
PODE_GERENCIAR_INT = ["gestor"]


# ── DB ──────────────────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS igrejas (
            id        SERIAL PRIMARY KEY,
            nome      TEXT NOT NULL,
            endereco  TEXT,
            logo      TEXT,
            status    TEXT NOT NULL DEFAULT 'pendente',
            criado_em TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS integrantes (
            id         SERIAL PRIMARY KEY,
            igreja_id  INTEGER REFERENCES igrejas(id) ON DELETE CASCADE,
            nome       TEXT NOT NULL,
            email      TEXT NOT NULL,
            senha_hash TEXT NOT NULL,
            whatsapp   TEXT,
            nivel      TEXT NOT NULL DEFAULT 'voluntario',
            foto       TEXT,
            criado_em  TIMESTAMP DEFAULT NOW(),
            UNIQUE(email)
        );
        CREATE TABLE IF NOT EXISTS funcoes_integrante (
            id            SERIAL PRIMARY KEY,
            integrante_id INTEGER REFERENCES integrantes(id) ON DELETE CASCADE,
            nome          TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS escalas (
            id        SERIAL PRIMARY KEY,
            igreja_id INTEGER REFERENCES igrejas(id) ON DELETE CASCADE,
            data      DATE NOT NULL,
            evento    TEXT,
            criado_em TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS escala_slots (
            id            SERIAL PRIMARY KEY,
            escala_id     INTEGER REFERENCES escalas(id) ON DELETE CASCADE,
            integrante_id INTEGER REFERENCES integrantes(id) ON DELETE SET NULL,
            funcao        TEXT NOT NULL
        );
    """)
    # migrações seguras
    for sql in [
        "ALTER TABLE igrejas     ADD COLUMN IF NOT EXISTS logo     TEXT",
        "ALTER TABLE igrejas     ADD COLUMN IF NOT EXISTS status   TEXT DEFAULT 'pendente'",
        "ALTER TABLE integrantes ADD COLUMN IF NOT EXISTS whatsapp TEXT",
        "ALTER TABLE integrantes ADD COLUMN IF NOT EXISTS foto     TEXT",
        "ALTER TABLE integrantes ADD COLUMN IF NOT EXISTS igreja_id INTEGER",
        "ALTER TABLE escalas     ADD COLUMN IF NOT EXISTS igreja_id INTEGER",
    ]:
        try: cur.execute(sql)
        except: conn.rollback()
    conn.commit(); cur.close(); conn.close()

init_db()


# ── SENHAS (bcrypt) ─────────────────────────────────────────────
def hash_senha(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()

def verificar_senha(plain: str, hashed: str) -> bool:
    try:
        # suporte a hashes antigos SHA-256 durante migração
        import hashlib
        if hashed == hashlib.sha256(plain.encode()).hexdigest():
            return True
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def migrar_senha_se_necessario(integrante_id: int, plain: str, hashed: str):
    """Re-hash com bcrypt se ainda for SHA-256"""
    import hashlib
    if hashed == hashlib.sha256(plain.encode()).hexdigest():
        try:
            novo = hash_senha(plain)
            conn = get_conn(); cur = conn.cursor()
            cur.execute("UPDATE integrantes SET senha_hash=%s WHERE id=%s", (novo, integrante_id))
            conn.commit(); cur.close(); conn.close()
        except Exception:
            pass


# ── JWT ─────────────────────────────────────────────────────────
def criar_token(integrante_id: int, igreja_id: int, nivel: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {
        "sub": str(integrante_id),
        "igreja_id": igreja_id,
        "nivel": nivel,
        "exp": exp,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decodificar_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(401, "Token inválido ou expirado")


# ── AUTH DEPENDENCY ─────────────────────────────────────────────
def get_atual(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(401, "Token não fornecido")
    payload = decodificar_token(credentials.credentials)
    integrante_id = int(payload["sub"])
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT i.id, i.nome, i.email, i.nivel, i.whatsapp, i.foto, i.igreja_id,
               ig.nome as igreja_nome, ig.status as igreja_status
        FROM integrantes i
        JOIN igrejas ig ON ig.id = i.igreja_id
        WHERE i.id = %s
    """, (integrante_id,))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        raise HTTPException(401, "Integrante não encontrado")
    if row["igreja_status"] != "ativa":
        raise HTTPException(403, "Igreja ainda não aprovada")
    return dict(row)

def requer_nivel(niveis: list):
    def check(atual=Depends(get_atual)):
        if atual["nivel"] not in niveis:
            raise HTTPException(403, "Sem permissão para esta ação")
        return atual
    return check

def check_super(key: str):
    if not SUPER_ADMIN_KEY or key != SUPER_ADMIN_KEY:
        raise HTTPException(403, "Chave de admin inválida")


# ── VALIDAÇÕES ──────────────────────────────────────────────────
def sanitizar(texto: str) -> str:
    return texto.strip()[:500] if texto else ""

def validar_whatsapp(w: Optional[str]) -> Optional[str]:
    if not w: return None
    digits = re.sub(r'\D', '', w)
    if len(digits) < 10 or len(digits) > 13:
        return None
    return digits

def validar_nivel(nivel: str):
    if nivel not in NIVEIS:
        raise HTTPException(400, f"Nível inválido. Use: {', '.join(NIVEIS)}")


# ── MODELS ─────────────────────────────────────────────────────
class SolicitacaoCadastro(BaseModel):
    igreja_nome:      str
    igreja_endereco:  Optional[str] = None
    igreja_logo:      Optional[str] = None
    gestor_nome:      str
    gestor_email:     str
    gestor_senha:     str

    @field_validator("gestor_email")
    @classmethod
    def email_valido(cls, v):
        if not v or "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("E-mail inválido")
        return v.lower().strip()

    @field_validator("gestor_senha")
    @classmethod
    def senha_forte(cls, v):
        if not v or len(v) < 6:
            raise ValueError("Senha deve ter ao menos 6 caracteres")
        return v

    @field_validator("igreja_nome", "gestor_nome")
    @classmethod
    def nao_vazio(cls, v):
        if not v or not v.strip():
            raise ValueError("Campo obrigatório")
        return v.strip()

class LoginData(BaseModel):
    email: str
    senha: str

    @field_validator("email")
    @classmethod
    def email_lower(cls, v):
        return v.lower().strip() if v else v

class IntegranteCriar(BaseModel):
    nome:      str
    email:     str
    senha:     str
    whatsapp:  Optional[str] = None
    nivel:     str = "voluntario"
    funcoes:   List[str] = []
    foto:      Optional[str] = None

    @field_validator("email")
    @classmethod
    def email_lower(cls, v):
        if not v or "@" not in v:
            raise ValueError("E-mail inválido")
        return v.lower().strip()

    @field_validator("senha")
    @classmethod
    def senha_minima(cls, v):
        if not v or len(v) < 6:
            raise ValueError("Senha deve ter ao menos 6 caracteres")
        return v

    @field_validator("nome")
    @classmethod
    def nome_valido(cls, v):
        if not v or not v.strip():
            raise ValueError("Nome é obrigatório")
        return v.strip()

class IntegranteEditar(BaseModel):
    nome:      str
    email:     str
    senha:     Optional[str] = None
    whatsapp:  Optional[str] = None
    nivel:     str
    funcoes:   List[str] = []
    foto:      Optional[str] = None

    @field_validator("email")
    @classmethod
    def email_lower(cls, v):
        if not v or "@" not in v:
            raise ValueError("E-mail inválido")
        return v.lower().strip()

class EscalaSlotIn(BaseModel):
    integrante_id: int
    funcao:        str

class EscalaDados(BaseModel):
    data:    str
    evento:  Optional[str] = ""
    slots:   List[EscalaSlotIn]

    @field_validator("data")
    @classmethod
    def data_valida(cls, v):
        if not v:
            raise ValueError("Data é obrigatória")
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Data inválida. Use o formato YYYY-MM-DD")
        return v

class IgrejaEditar(BaseModel):
    nome:      str
    endereco:  Optional[str] = None
    logo:      Optional[str] = None


# ── WHATSAPP ────────────────────────────────────────────────────
def enviar_whatsapp(numero: str, mensagem: str):
    if not EVOLUTION_API_URL: return
    try:
        n = re.sub(r'\D', '', numero)
        if len(n) == 11: n = '55' + n
        elif len(n) == 10: n = '55' + n
        payload = json.dumps({"number": n, "text": mensagem}).encode()
        url = f"{EVOLUTION_API_URL}/message/sendText/{EVOLUTION_INSTANCE}"
        req = urllib.request.Request(url, data=payload,
            headers={"Content-Type":"application/json","apikey":EVOLUTION_API_KEY}, method="POST")
        urllib.request.urlopen(req, timeout=8)
    except Exception:
        pass

def notificar_escalado(integrante_id: int, data_str: str, evento: str, funcao: str):
    try:
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT nome, whatsapp FROM integrantes WHERE id=%s", (integrante_id,))
        row = cur.fetchone(); cur.close(); conn.close()
        if not row or not row["whatsapp"]: return
        nome = row["nome"].split()[0]
        ev   = f" — {evento}" if evento else ""
        msg  = (f"🎵 *Praizy* — Você foi escalado!\n\n"
                f"Olá, *{nome}*!\n\n"
                f"📅 *Data:* {data_str}{ev}\n"
                f"🎸 *Função:* {funcao}\n\n"
                f"Acesse o Praizy para mais detalhes.")
        enviar_whatsapp(row["whatsapp"], msg)
    except Exception:
        pass


# ── CADASTRO PÚBLICO ────────────────────────────────────────────
@app.post("/cadastro/solicitar", status_code=201)
def solicitar_cadastro(data: SolicitacaoCadastro):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE email=%s", (data.gestor_email,))
    if cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(400, "E-mail já cadastrado")
    cur.execute(
        "INSERT INTO igrejas (nome,endereco,logo,status) VALUES (%s,%s,%s,'pendente') RETURNING id",
        (sanitizar(data.igreja_nome), sanitizar(data.igreja_endereco or ""), data.igreja_logo)
    )
    igreja_id = cur.fetchone()["id"]
    cur.execute(
        "INSERT INTO integrantes (igreja_id,nome,email,senha_hash,nivel) VALUES (%s,%s,%s,%s,'gestor') RETURNING id",
        (igreja_id, sanitizar(data.gestor_nome), data.gestor_email, hash_senha(data.gestor_senha))
    )
    conn.commit(); cur.close(); conn.close()
    return {"mensagem": "Solicitação enviada! Aguarde a aprovação do administrador."}


# ── SUPER ADMIN ─────────────────────────────────────────────────
@app.get("/admin/igrejas")
def admin_listar(key: str):
    check_super(key)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        SELECT ig.id, ig.nome, ig.endereco, ig.status, ig.criado_em,
               i.nome as gestor_nome, i.email as gestor_email
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
    return {"mensagem": "Igreja aprovada!"}

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


# ── AUTH ────────────────────────────────────────────────────────
@app.post("/auth/login")
def login(data: LoginData):
    if not data.email or not data.senha:
        raise HTTPException(400, "E-mail e senha são obrigatórios")
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "SELECT id,nome,email,senha_hash,nivel,whatsapp,foto,igreja_id FROM integrantes WHERE email=%s",
        (data.email,)
    )
    row = cur.fetchone()
    if not row or not verificar_senha(data.senha, row["senha_hash"]):
        cur.close(); conn.close()
        raise HTTPException(401, "E-mail ou senha incorretos")
    cur.execute("SELECT status,nome FROM igrejas WHERE id=%s", (row["igreja_id"],))
    ig = cur.fetchone()
    if ig["status"] == "pendente":
        cur.close(); conn.close()
        raise HTTPException(403, f"A igreja '{ig['nome']}' ainda aguarda aprovação.")
    if ig["status"] == "rejeitada":
        cur.close(); conn.close()
        raise HTTPException(403, f"O cadastro da igreja '{ig['nome']}' foi rejeitado.")
    # migra SHA-256 → bcrypt silenciosamente
    migrar_senha_se_necessario(row["id"], data.senha, row["senha_hash"])
    token = criar_token(row["id"], row["igreja_id"], row["nivel"])
    cur.close(); conn.close()
    return {
        "token": token,
        "integrante": {"id":row["id"],"nome":row["nome"],"email":row["email"],
                       "nivel":row["nivel"],"foto":row["foto"],"igreja_id":row["igreja_id"]},
        "igreja": {"nome": ig["nome"], "status": ig["status"]}
    }

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
                (sanitizar(data.nome), sanitizar(data.endereco or ""), data.logo, atual["igreja_id"]))
    conn.commit(); cur.close(); conn.close()
    return {"mensagem": "Igreja atualizada"}


# ── INTEGRANTES ─────────────────────────────────────────────────
@app.get("/integrantes")
def listar_integrantes(atual=Depends(get_atual)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id,nome,email,whatsapp,nivel,foto FROM integrantes WHERE igreja_id=%s ORDER BY nome",
                (atual["igreja_id"],))
    rows = cur.fetchall(); result = []
    for r in rows:
        cur.execute("SELECT nome FROM funcoes_integrante WHERE integrante_id=%s", (r["id"],))
        d = dict(r); d["funcoes"] = [x["nome"] for x in cur.fetchall()]; result.append(d)
    cur.close(); conn.close()
    return result

@app.post("/integrantes", status_code=201)
def criar_integrante(data: IntegranteCriar, atual=Depends(requer_nivel(PODE_GERENCIAR_INT))):
    validar_nivel(data.nivel)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE email=%s", (data.email,))
    if cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(400, "E-mail já cadastrado")
    cur.execute(
        "INSERT INTO integrantes (igreja_id,nome,email,senha_hash,whatsapp,nivel,foto) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (atual["igreja_id"], sanitizar(data.nome), data.email, hash_senha(data.senha),
         validar_whatsapp(data.whatsapp), data.nivel, data.foto)
    )
    iid = cur.fetchone()["id"]
    for f in data.funcoes:
        if f.strip():
            cur.execute("INSERT INTO funcoes_integrante (integrante_id,nome) VALUES (%s,%s)", (iid, sanitizar(f)))
    conn.commit(); cur.close(); conn.close()
    return {"id": iid}

@app.put("/integrantes/{iid}")
def editar_integrante(iid: int, data: IntegranteEditar, atual=Depends(requer_nivel(PODE_GERENCIAR_INT))):
    validar_nivel(data.nivel)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE id=%s AND igreja_id=%s", (iid, atual["igreja_id"]))
    if not cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(404, "Integrante não encontrado")
    if data.senha and len(data.senha) >= 6:
        cur.execute("UPDATE integrantes SET nome=%s,email=%s,senha_hash=%s,whatsapp=%s,nivel=%s,foto=%s WHERE id=%s",
                    (sanitizar(data.nome), data.email, hash_senha(data.senha),
                     validar_whatsapp(data.whatsapp), data.nivel, data.foto, iid))
    else:
        cur.execute("UPDATE integrantes SET nome=%s,email=%s,whatsapp=%s,nivel=%s,foto=%s WHERE id=%s",
                    (sanitizar(data.nome), data.email, validar_whatsapp(data.whatsapp), data.nivel, data.foto, iid))
    cur.execute("DELETE FROM funcoes_integrante WHERE integrante_id=%s", (iid,))
    for f in data.funcoes:
        if f.strip():
            cur.execute("INSERT INTO funcoes_integrante (integrante_id,nome) VALUES (%s,%s)", (iid, sanitizar(f)))
    conn.commit(); cur.close(); conn.close()
    return {"id": iid}

@app.delete("/integrantes/{iid}", status_code=204)
def deletar_integrante(iid: int, atual=Depends(requer_nivel(PODE_GERENCIAR_INT))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM integrantes WHERE id=%s AND igreja_id=%s", (iid, atual["igreja_id"]))
    if cur.rowcount == 0:
        cur.close(); conn.close()
        raise HTTPException(404, "Não encontrado")
    conn.commit(); cur.close(); conn.close()


# ── ESCALAS ─────────────────────────────────────────────────────
@app.get("/escalas")
def listar_escalas(atual=Depends(get_atual)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id,data::text,evento FROM escalas WHERE igreja_id=%s ORDER BY data DESC",
                (atual["igreja_id"],))
    escalas = cur.fetchall(); result = []
    for e in escalas:
        cur.execute("""
            SELECT es.funcao, i.id as integrante_id, i.nome as integrante_nome, i.foto as integrante_foto
            FROM escala_slots es LEFT JOIN integrantes i ON i.id=es.integrante_id
            WHERE es.escala_id=%s
        """, (e["id"],))
        result.append({"id":e["id"],"data":e["data"],"evento":e["evento"],
                       "slots":[dict(s) for s in cur.fetchall()]})
    cur.close(); conn.close()
    return result

@app.post("/escalas", status_code=201)
def criar_escala(data: EscalaDados, atual=Depends(requer_nivel(PODE_CRIAR_ESCALA))):
    conn = get_conn(); cur = conn.cursor()
    # valida que todos os integrantes pertencem à mesma igreja
    for s in data.slots:
        cur.execute("SELECT id FROM integrantes WHERE id=%s AND igreja_id=%s", (s.integrante_id, atual["igreja_id"]))
        if not cur.fetchone():
            cur.close(); conn.close()
            raise HTTPException(400, f"Integrante {s.integrante_id} não pertence a esta igreja")
    cur.execute("INSERT INTO escalas (igreja_id,data,evento) VALUES (%s,%s,%s) RETURNING id",
                (atual["igreja_id"], data.data, sanitizar(data.evento or "")))
    eid = cur.fetchone()["id"]
    for s in data.slots:
        cur.execute("INSERT INTO escala_slots (escala_id,integrante_id,funcao) VALUES (%s,%s,%s)",
                    (eid, s.integrante_id, sanitizar(s.funcao)))
    conn.commit(); cur.close(); conn.close()
    for s in data.slots:
        notificar_escalado(s.integrante_id, data.data, data.evento or "", s.funcao)
    return {"id": eid}

@app.put("/escalas/{eid}")
def editar_escala(eid: int, data: EscalaDados, atual=Depends(requer_nivel(PODE_EDITAR_ESCALA))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM escalas WHERE id=%s AND igreja_id=%s", (eid, atual["igreja_id"]))
    if not cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(404, "Escala não encontrada")
    cur.execute("UPDATE escalas SET data=%s,evento=%s WHERE id=%s",
                (data.data, sanitizar(data.evento or ""), eid))
    cur.execute("DELETE FROM escala_slots WHERE escala_id=%s", (eid,))
    for s in data.slots:
        cur.execute("INSERT INTO escala_slots (escala_id,integrante_id,funcao) VALUES (%s,%s,%s)",
                    (eid, s.integrante_id, sanitizar(s.funcao)))
    conn.commit(); cur.close(); conn.close()
    for s in data.slots:
        notificar_escalado(s.integrante_id, data.data, data.evento or "", s.funcao)
    return {"id": eid}

@app.delete("/escalas/{eid}", status_code=204)
def deletar_escala(eid: int, atual=Depends(requer_nivel(PODE_CRIAR_ESCALA))):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM escalas WHERE id=%s AND igreja_id=%s", (eid, atual["igreja_id"]))
    if cur.rowcount == 0:
        cur.close(); conn.close()
        raise HTTPException(404, "Não encontrada")
    conn.commit(); cur.close(); conn.close()


# ── SUBSTITUIÇÕES ───────────────────────────────────────────────
@app.get("/substitutos/{iid}")
def substitutos(iid: int, atual=Depends(get_atual)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM integrantes WHERE id=%s AND igreja_id=%s", (iid, atual["igreja_id"]))
    if not cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(404, "Não encontrado")
    cur.execute("SELECT nome FROM funcoes_integrante WHERE integrante_id=%s", (iid,))
    funcoes = [r["nome"] for r in cur.fetchall()]; result = []
    for f in funcoes:
        cur.execute("""
            SELECT i.id, i.nome FROM integrantes i
            JOIN funcoes_integrante fi ON fi.integrante_id=i.id
            WHERE fi.nome=%s AND i.id!=%s AND i.igreja_id=%s
        """, (f, iid, atual["igreja_id"]))
        result.append({"funcao": f, "substitutos": [dict(r) for r in cur.fetchall()]})
    cur.close(); conn.close()
    return result


@app.get("/health")
def health(): return {"status": "ok"}
