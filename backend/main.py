from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from typing import Optional
from datetime import date, datetime
import pandas as pd
import re
import io

class Settings(BaseSettings):
    database_url: str = "postgresql://vulnuser:vuln2024secure@db:5432/vulnerabilidades"
    class Config:
        env_file = ".env"

settings = Settings()
async_url = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")
engine = create_async_engine(async_url, pool_size=10, max_overflow=20)
Session = async_sessionmaker(engine, expire_on_commit=False)

app = FastAPI(title="Vulnerabilidades GoC", version="2.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

async def db():
    async with Session() as s:
        yield s

class VulnIn(BaseModel):
    tipo: Optional[str] = "Vulnerabilidad"
    detalle: str
    subgerencia: Optional[str] = None
    area: Optional[str] = None
    solicitante: Optional[str] = None
    responsable_om: Optional[str] = None
    responsable_ing: Optional[str] = None
    prioridad: Optional[int] = 1
    fecha_declaracion: Optional[date] = None
    fecha_compromiso: Optional[date] = None
    fecha_solucion: Optional[date] = None
    estado_om: Optional[str] = "PENDIENTE"
    estado_ing: Optional[str] = None
    condicion_ing: Optional[str] = None
    obs_om: Optional[str] = None
    obs_ing: Optional[str] = None

class VulnPatch(BaseModel):
    tipo: Optional[str] = None
    detalle: Optional[str] = None
    subgerencia: Optional[str] = None
    area: Optional[str] = None
    solicitante: Optional[str] = None
    responsable_om: Optional[str] = None
    responsable_ing: Optional[str] = None
    prioridad: Optional[int] = None
    fecha_declaracion: Optional[date] = None
    fecha_compromiso: Optional[date] = None
    fecha_solucion: Optional[date] = None
    estado_om: Optional[str] = None
    estado_ing: Optional[str] = None
    condicion_ing: Optional[str] = None
    obs_om: Optional[str] = None
    obs_ing: Optional[str] = None

class NotaIn(BaseModel):
    autor: Optional[str] = "Usuario"
    texto: str

# ── Helpers ────────────────────────────────────────────────────────────────────

def title_case(val):
    if not val: return None
    s = str(val).strip()
    if not s or s.lower() in ('nan','none','nat'): return None
    return s.title()

def safe(val):
    if val is None: return None
    if isinstance(val, float) and pd.isna(val): return None
    s = str(val).strip()
    return s if s and s.lower() not in ('nan','none','nat') else None

def safe_date(val):
    if val is None: return None
    if isinstance(val, float) and pd.isna(val): return None
    s = str(val).strip().upper()
    if any(x in s for x in ['SIN', 'FECHA', 'COMPROMISO', 'N/A', 'NA']): return None
    if isinstance(val, (date, datetime)):
        return val if isinstance(val, date) else val.date()
    try: return pd.to_datetime(val).date()
    except: return None

def safe_int(val):
    try: return int(float(val))
    except: return None

def norm_estado(val):
    if not val: return "PENDIENTE"
    v = str(val).strip().upper()
    valid = ['PENDIENTE','EN CURSO','TERMINADA','CERRADO','RENOVACION','REVISAR']
    return v if v in valid else "PENDIENTE"

def norm_subgerencia(val):
    if not val: return None
    v = str(val).strip().replace('\n',' ')
    if not v or v.lower() in ('nan','none'): return None
    return v.upper()

def split_detalle_obs(raw_detalle):
    """
    Separa el detalle de la respuesta O&M embebida.
    Ejemplo:
      "ACS sin redundancia\nRespuesta O&M: Se mantiene..."
      -> detalle = "ACS sin redundancia"
      -> obs_om  = "Se mantiene..."
    """
    if not raw_detalle:
        return None, None
    
    # Patrones que indican inicio de respuesta O&M
    patterns = [
        r'\n[Rr]espuesta\s+[Oo](&|and|y)\s*[Mm]\s*[:.]',
        r'\n[Rr]espuesta\s+[Oo]&[Mm]\s*[:.]',
        r'\n[Rr]espuesta\s+[Oo]&[Mm]\s*\n',
        r'\nRespuesta\s*[:.]',
    ]
    
    texto = str(raw_detalle).strip()
    
    for pattern in patterns:
        match = re.search(pattern, texto)
        if match:
            detalle = texto[:match.start()].strip()
            obs = texto[match.end():].strip()
            return detalle or texto, obs or None
    
    return texto, None

# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.3"}

@app.get("/api/dashboard")
async def dashboard(s: AsyncSession = Depends(db)):
    total       = await s.execute(text("SELECT COUNT(*) FROM vulnerabilidades"))
    estados     = await s.execute(text("SELECT estado_om, COUNT(*) FROM vulnerabilidades GROUP BY estado_om ORDER BY COUNT(*) DESC"))
    prioridades = await s.execute(text("SELECT prioridad, COUNT(*) FROM vulnerabilidades WHERE prioridad IS NOT NULL GROUP BY prioridad ORDER BY prioridad"))
    subgs       = await s.execute(text("SELECT subgerencia, COUNT(*) FROM vulnerabilidades WHERE subgerencia IS NOT NULL GROUP BY subgerencia ORDER BY COUNT(*) DESC LIMIT 10"))
    responsables= await s.execute(text("SELECT responsable_ing, COUNT(*) FROM vulnerabilidades WHERE responsable_ing IS NOT NULL GROUP BY responsable_ing ORDER BY COUNT(*) DESC LIMIT 10"))
    vencidas    = await s.execute(text("SELECT COUNT(*) FROM vulnerabilidades WHERE fecha_compromiso < NOW() AND estado_om NOT IN ('TERMINADA','CERRADO')"))
    crit_data   = await s.execute(text("""
        SELECT prioridad, estado_om, COUNT(*) 
        FROM vulnerabilidades 
        WHERE prioridad IS NOT NULL 
        GROUP BY prioridad, estado_om ORDER BY prioridad, estado_om
    """))
    return {
        "total": total.scalar(),
        "vencidas": vencidas.scalar(),
        "por_estado": [{"estado": r[0], "total": r[1]} for r in estados],
        "por_prioridad": [{"prioridad": r[0], "total": r[1]} for r in prioridades],
        "por_subgerencia": [{"subgerencia": r[0], "total": r[1]} for r in subgs],
        "por_responsable": [{"responsable": r[0], "total": r[1]} for r in responsables],
        "criticidad_estado": [{"prioridad": r[0], "estado": r[1], "total": r[2]} for r in crit_data],
    }

@app.get("/api/vulnerabilidades")
async def listar(
    s: AsyncSession = Depends(db),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    q: Optional[str] = None,
    estado: Optional[str] = None,
    prioridad: Optional[int] = None,
    subgerencia: Optional[str] = None,
    responsable_ing: Optional[str] = None,
    sort: str = "id",
    dir: str = "asc",
):
    where, params = [], {}
    if q:
        where.append("(detalle ILIKE :q OR area ILIKE :q OR responsable_ing ILIKE :q OR subgerencia ILIKE :q OR solicitante ILIKE :q OR tipo ILIKE :q)")
        params["q"] = f"%{q}%"
    if estado:
        where.append("estado_om = :estado"); params["estado"] = estado
    if prioridad:
        where.append("prioridad = :prioridad"); params["prioridad"] = prioridad
    if subgerencia:
        where.append("subgerencia = :subgerencia"); params["subgerencia"] = subgerencia
    if responsable_ing:
        where.append("responsable_ing ILIKE :resp"); params["resp"] = f"%{responsable_ing}%"

    w  = ("WHERE " + " AND ".join(where)) if where else ""
    safe_cols = {"id","prioridad","estado_om","subgerencia","area","tipo","fecha_declaracion","fecha_compromiso","updated_at"}
    sc = sort if sort in safe_cols else "id"
    sd = "DESC" if dir.lower() == "desc" else "ASC"
    offset = (page - 1) * limit

    cnt  = await s.execute(text(f"SELECT COUNT(*) FROM vulnerabilidades {w}"), params)
    rows = await s.execute(text(f"""
        SELECT id, tipo, detalle, subgerencia, area, solicitante,
               responsable_om, responsable_ing, prioridad,
               fecha_declaracion, fecha_compromiso, fecha_solucion,
               estado_om, estado_ing, condicion_ing, updated_at
        FROM vulnerabilidades {w}
        ORDER BY {sc} {sd}
        LIMIT :limit OFFSET :offset
    """), {**params, "limit": limit, "offset": offset})

    return {"total": cnt.scalar(), "page": page, "limit": limit,
            "items": [dict(r._mapping) for r in rows]}

@app.get("/api/vulnerabilidades/{vid}")
async def obtener(vid: int, s: AsyncSession = Depends(db)):
    row = await s.execute(text("SELECT * FROM vulnerabilidades WHERE id = :id"), {"id": vid})
    r = row.fetchone()
    if not r: raise HTTPException(404, "No encontrado")
    vuln = dict(r._mapping)
    notas = await s.execute(text("SELECT * FROM notas WHERE vulnerabilidad_id = :id ORDER BY created_at DESC"), {"id": vid})
    hist  = await s.execute(text("SELECT * FROM historial WHERE vulnerabilidad_id = :id ORDER BY created_at DESC LIMIT 30"), {"id": vid})
    vuln["notas"]     = [dict(n._mapping) for n in notas]
    vuln["historial"] = [dict(h._mapping) for h in hist]
    return vuln

@app.post("/api/vulnerabilidades", status_code=201)
async def crear(body: VulnIn, s: AsyncSession = Depends(db)):
    d = body.model_dump(exclude_none=True)
    cols = ", ".join(d.keys()); vals = ", ".join(f":{k}" for k in d.keys())
    res  = await s.execute(text(f"INSERT INTO vulnerabilidades ({cols}) VALUES ({vals}) RETURNING id"), d)
    await s.commit()
    return {"id": res.scalar()}

@app.patch("/api/vulnerabilidades/{vid}")
async def actualizar(vid: int, body: VulnPatch, s: AsyncSession = Depends(db)):
    row = await s.execute(text("SELECT * FROM vulnerabilidades WHERE id = :id"), {"id": vid})
    cur = row.fetchone()
    if not cur: raise HTTPException(404, "No encontrado")
    updates = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if not updates: return {"message": "Sin cambios"}
    cur_dict = dict(cur._mapping)
    for campo, nuevo in updates.items():
        anterior = cur_dict.get(campo)
        if str(anterior) != str(nuevo):
            await s.execute(text(
                "INSERT INTO historial (vulnerabilidad_id, campo, valor_anterior, valor_nuevo) VALUES (:id, :c, :a, :n)"
            ), {"id": vid, "c": campo, "a": str(anterior), "n": str(nuevo)})
    set_sql = ", ".join(f"{k} = :{k}" for k in updates)
    await s.execute(text(f"UPDATE vulnerabilidades SET {set_sql} WHERE id = :id"), {**updates, "id": vid})
    await s.commit()
    return {"message": "OK"}

@app.delete("/api/vulnerabilidades/{vid}")
async def eliminar(vid: int, s: AsyncSession = Depends(db)):
    res = await s.execute(text("DELETE FROM vulnerabilidades WHERE id = :id RETURNING id"), {"id": vid})
    if not res.fetchone(): raise HTTPException(404, "No encontrado")
    await s.commit()
    return {"message": "Eliminado"}

@app.post("/api/vulnerabilidades/{vid}/notas", status_code=201)
async def agregar_nota(vid: int, body: NotaIn, s: AsyncSession = Depends(db)):
    row = await s.execute(text("SELECT id FROM vulnerabilidades WHERE id = :id"), {"id": vid})
    if not row.fetchone(): raise HTTPException(404, "No encontrado")
    await s.execute(text(
        "INSERT INTO notas (vulnerabilidad_id, autor, texto) VALUES (:id, :autor, :texto)"
    ), {"id": vid, "autor": body.autor, "texto": body.texto})
    await s.commit()
    return {"message": "Nota agregada"}

@app.get("/api/filtros")
async def filtros(s: AsyncSession = Depends(db)):
    subgs = await s.execute(text("SELECT DISTINCT subgerencia FROM vulnerabilidades WHERE subgerencia IS NOT NULL ORDER BY subgerencia"))
    resps = await s.execute(text("SELECT DISTINCT responsable_ing FROM vulnerabilidades WHERE responsable_ing IS NOT NULL ORDER BY responsable_ing"))
    areas = await s.execute(text("SELECT DISTINCT area FROM vulnerabilidades WHERE area IS NOT NULL ORDER BY area"))
    return {
        "subgerencias": [r[0] for r in subgs],
        "responsables_ing": [r[0] for r in resps],
        "areas": [r[0] for r in areas],
    }

@app.post("/api/importar")
async def importar(file: UploadFile = File(...), s: AsyncSession = Depends(db)):
    content = await file.read()
    try:
        eng = "xlrd" if file.filename.endswith(".xls") else "openpyxl"
        xl  = pd.ExcelFile(io.BytesIO(content), engine=eng)
        inserted, skipped = 0, 0

        for sheet in xl.sheet_names:
            try:
                df = xl.parse(sheet, header=0)
                df.columns = [str(c).strip() for c in df.columns]
                df = df[[c for c in df.columns if not c.startswith('Unnamed')]]
                if "DETALLE" not in df.columns: continue

                for _, row in df.iterrows():
                    raw_det = safe(row.get("DETALLE"))
                    if not raw_det: skipped += 1; continue

                    # Separar detalle de respuesta O&M embebida
                    detalle, obs_om_extra = split_detalle_obs(raw_det)
                    
                    # Si ya hay obs_om en columna propia, concatenar
                    obs_om_col = safe(row.get("OBSERVACIONES O&M"))
                    if obs_om_extra and obs_om_col:
                        obs_om_final = obs_om_col + "\n\n" + obs_om_extra
                    else:
                        obs_om_final = obs_om_col or obs_om_extra

                    await s.execute(text("""
                        INSERT INTO vulnerabilidades
                            (tipo, detalle, subgerencia, area, solicitante,
                             responsable_om, responsable_ing, prioridad,
                             fecha_declaracion, fecha_compromiso, fecha_solucion,
                             estado_om, estado_ing, condicion_ing, obs_om, obs_ing)
                        VALUES
                            (:tipo, :detalle, :subgerencia, :area, :solicitante,
                             :responsable_om, :responsable_ing, :prioridad,
                             :fecha_declaracion, :fecha_compromiso, :fecha_solucion,
                             :estado_om, :estado_ing, :condicion_ing, :obs_om, :obs_ing)
                    """), {
                        "tipo":              title_case(row.get("TIPO")) or "Vulnerabilidad",
                        "detalle":           detalle,
                        "subgerencia":       norm_subgerencia(row.get("SUBGERENCIA")),
                        "area":              title_case(row.get("AREA")),
                        "solicitante":       title_case(row.get("SOLICITANTE")),
                        "responsable_om":    title_case(row.get("RESPONSABLE")),
                        "responsable_ing":   title_case(row.get("RESPONSABLE ING")),
                        "prioridad":         safe_int(row.get("PRIORIDAD")),
                        "fecha_declaracion": safe_date(row.get("FECHA DECLARACION")),
                        "fecha_compromiso":  safe_date(row.get("FECHA COMPROMISO")),
                        "fecha_solucion":    safe_date(row.get("FECHA SOLUCION")),
                        "estado_om":         norm_estado(row.get("ESTADO O&M")),
                        "estado_ing":        safe(row.get("ESTADO ING")),
                        "condicion_ing":     safe(row.get("CONDICION ING")),
                        "obs_om":            obs_om_final,
                        "obs_ing":           safe(row.get("OBSERVACIONES ING")),
                    })
                    inserted += 1
            except Exception as e:
                skipped += 1; continue

        await s.commit()
        return {"inserted": inserted, "skipped": skipped}
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")
