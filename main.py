from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import psycopg2
import psycopg2.extras
import os
import hashlib
import secrets
import re

app = FastAPI(title="Praizy API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL")
security = HTTPBearer(auto_error=False)


def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def hash_senha(senha: str) -> str:
    return hashlib.sha256(senha.encode()).hexdigest()


def gerar_token() -> str:
    return secrets.token_hex(32)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            criado_em TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS sessoes (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            criado_em TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS membros (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            foto TEXT,
            criado_em TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS funcoes (
            id SERIAL PRIMARY KEY,
            membro_id INTEGER REFERENCES membros(id) ON DELETE CASCADE,
            nome TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS escalas (
            id SERIAL PRIMARY KEY,
            data DATE NOT NULL,
            evento TEXT,
            criado_em TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS escala_slots (
            id SERIAL PRIMARY KEY,
            escala_id INTEGER REFERENCES escalas(id) ON DELETE CASCADE,
            membro_id INTEGER REFERENCES membros(id) ON DELETE SET NULL,
            funcao TEXT NOT NULL
        );
    """)
    cur.execute("ALTER TABLE membros ADD COLUMN IF NOT EXISTS foto TEXT;")
    conn.commit()
    cur.close()
    conn.close()


init_db()


# ── Auth helper ────────────────────────────────────────────────
def get_usuario_atual(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(401, "Token não fornecido")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.nome, u.email
        FROM sessoes s
        JOIN usuarios u ON u.id = s.usuario_id
        WHERE s.token = %s
    """, (credentials.credentials,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()
    if not usuario:
        raise HTTPException(401, "Sessão inválida ou expirada")
    return dict(usuario)


# ── Models ─────────────────────────────────────────────────────
class UsuarioCadastro(BaseModel):
    nome: str
    email: str
    senha: str

class UsuarioLogin(BaseModel):
    email: str
    senha: str

class MembroCreate(BaseModel):
    nome: str
    funcoes: List[str]
    foto: Optional[str] = None

class MembroUpdate(BaseModel):
    nome: str
    funcoes: List[str]
    foto: Optional[str] = None

class EscalaSlotIn(BaseModel):
    membro_id: int
    funcao: str

class EscalaCreate(BaseModel):
    data: str
    evento: Optional[str] = ""
    slots: List[EscalaSlotIn]


# ── Auth endpoints ─────────────────────────────────────────────
@app.post("/auth/cadastro", status_code=201)
def cadastrar_usuario(data: UsuarioCadastro):
    if not data.nome.strip():
        raise HTTPException(400, "Nome é obrigatório")
    if not data.email.strip() or "@" not in data.email:
        raise HTTPException(400, "E-mail inválido")
    if len(data.senha) < 6:
        raise HTTPException(400, "A senha deve ter ao menos 6 caracteres")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuarios WHERE email = %s", (data.email.lower().strip(),))
    if cur.fetchone():
        cur.close(); conn.close()
        raise HTTPException(400, "E-mail já cadastrado")
    cur.execute(
        "INSERT INTO usuarios (nome, email, senha_hash) VALUES (%s, %s, %s) RETURNING id, nome, email",
        (data.nome.strip(), data.email.lower().strip(), hash_senha(data.senha))
    )
    usuario = cur.fetchone()
    token = gerar_token()
    cur.execute("INSERT INTO sessoes (usuario_id, token) VALUES (%s, %s)", (usuario["id"], token))
    conn.commit()
    cur.close(); conn.close()
    return {"token": token, "usuario": {"id": usuario["id"], "nome": usuario["nome"], "email": usuario["email"]}}


@app.post("/auth/login")
def login(data: UsuarioLogin):
    if not data.email or not data.senha:
        raise HTTPException(400, "E-mail e senha são obrigatórios")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, nome, email FROM usuarios WHERE email = %s AND senha_hash = %s",
        (data.email.lower().strip(), hash_senha(data.senha))
    )
    usuario = cur.fetchone()
    if not usuario:
        cur.close(); conn.close()
        raise HTTPException(401, "E-mail ou senha incorretos")
    token = gerar_token()
    cur.execute("INSERT INTO sessoes (usuario_id, token) VALUES (%s, %s)", (usuario["id"], token))
    conn.commit()
    cur.close(); conn.close()
    return {"token": token, "usuario": {"id": usuario["id"], "nome": usuario["nome"], "email": usuario["email"]}}


@app.post("/auth/logout", status_code=204)
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM sessoes WHERE token = %s", (credentials.credentials,))
    conn.commit()
    cur.close(); conn.close()


@app.get("/auth/me")
def me(usuario=Depends(get_usuario_atual)):
    return usuario


# ── Membros ────────────────────────────────────────────────────
@app.get("/membros")
def listar_membros(usuario=Depends(get_usuario_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, nome, foto FROM membros ORDER BY nome")
    membros = cur.fetchall()
    result = []
    for m in membros:
        cur.execute("SELECT nome FROM funcoes WHERE membro_id = %s", (m["id"],))
        funcoes = [r["nome"] for r in cur.fetchall()]
        result.append({"id": m["id"], "nome": m["nome"], "foto": m["foto"], "funcoes": funcoes})
    cur.close(); conn.close()
    return result


@app.post("/membros", status_code=201)
def criar_membro(data: MembroCreate, usuario=Depends(get_usuario_atual)):
    if not data.nome.strip():
        raise HTTPException(400, "Nome é obrigatório")
    if not data.funcoes:
        raise HTTPException(400, "Informe ao menos uma função")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO membros (nome, foto) VALUES (%s, %s) RETURNING id", (data.nome.strip(), data.foto))
    membro_id = cur.fetchone()["id"]
    for f in data.funcoes:
        cur.execute("INSERT INTO funcoes (membro_id, nome) VALUES (%s, %s)", (membro_id, f.strip()))
    conn.commit()
    cur.close(); conn.close()
    return {"id": membro_id, "nome": data.nome, "foto": data.foto, "funcoes": data.funcoes}


@app.put("/membros/{membro_id}")
def editar_membro(membro_id: int, data: MembroUpdate, usuario=Depends(get_usuario_atual)):
    if not data.nome.strip():
        raise HTTPException(400, "Nome é obrigatório")
    if not data.funcoes:
        raise HTTPException(400, "Informe ao menos uma função")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM membros WHERE id = %s", (membro_id,))
    if not cur.fetchone():
        raise HTTPException(404, "Membro não encontrado")
    if data.foto is not None:
        cur.execute("UPDATE membros SET nome = %s, foto = %s WHERE id = %s", (data.nome.strip(), data.foto, membro_id))
    else:
        cur.execute("UPDATE membros SET nome = %s WHERE id = %s", (data.nome.strip(), membro_id))
    cur.execute("DELETE FROM funcoes WHERE membro_id = %s", (membro_id,))
    for f in data.funcoes:
        cur.execute("INSERT INTO funcoes (membro_id, nome) VALUES (%s, %s)", (membro_id, f.strip()))
    conn.commit()
    cur.close(); conn.close()
    return {"id": membro_id, "nome": data.nome, "funcoes": data.funcoes}


@app.delete("/membros/{membro_id}", status_code=204)
def deletar_membro(membro_id: int, usuario=Depends(get_usuario_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM membros WHERE id = %s", (membro_id,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Membro não encontrado")
    conn.commit()
    cur.close(); conn.close()


# ── Escalas ────────────────────────────────────────────────────
@app.get("/escalas")
def listar_escalas(usuario=Depends(get_usuario_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, data::text, evento FROM escalas ORDER BY data")
    escalas = cur.fetchall()
    result = []
    for e in escalas:
        cur.execute("""
            SELECT es.funcao, m.id as membro_id, m.nome as membro_nome, m.foto as membro_foto
            FROM escala_slots es
            LEFT JOIN membros m ON m.id = es.membro_id
            WHERE es.escala_id = %s
        """, (e["id"],))
        slots = cur.fetchall()
        result.append({"id": e["id"], "data": e["data"], "evento": e["evento"], "slots": [dict(s) for s in slots]})
    cur.close(); conn.close()
    return result


@app.post("/escalas", status_code=201)
def criar_escala(data: EscalaCreate, usuario=Depends(get_usuario_atual)):
    if not data.data:
        raise HTTPException(400, "Data é obrigatória")
    if not data.slots:
        raise HTTPException(400, "Escale ao menos um membro")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO escalas (data, evento) VALUES (%s, %s) RETURNING id", (data.data, data.evento))
    escala_id = cur.fetchone()["id"]
    for slot in data.slots:
        cur.execute("INSERT INTO escala_slots (escala_id, membro_id, funcao) VALUES (%s, %s, %s)", (escala_id, slot.membro_id, slot.funcao))
    conn.commit()
    cur.close(); conn.close()
    return {"id": escala_id}


@app.delete("/escalas/{escala_id}", status_code=204)
def deletar_escala(escala_id: int, usuario=Depends(get_usuario_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM escalas WHERE id = %s", (escala_id,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Escala não encontrada")
    conn.commit()
    cur.close(); conn.close()


# ── Substituições ──────────────────────────────────────────────
@app.get("/substitutos/{membro_id}")
def buscar_substitutos(membro_id: int, usuario=Depends(get_usuario_atual)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT nome FROM funcoes WHERE membro_id = %s", (membro_id,))
    funcoes = [r["nome"] for r in cur.fetchall()]
    result = []
    for f in funcoes:
        cur.execute("""
            SELECT m.id, m.nome FROM membros m
            JOIN funcoes f ON f.membro_id = m.id
            WHERE f.nome = %s AND m.id != %s
        """, (f, membro_id))
        subs = [dict(r) for r in cur.fetchall()]
        result.append({"funcao": f, "substitutos": subs})
    cur.close(); conn.close()
    return result


@app.get("/health")
def health():
    return {"status": "ok"}
