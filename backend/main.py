from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from typing import Optional
from datetime import date, datetime
import pandas as pd, re, io

class Settings(BaseSettings):
    database_url: str = "postgresql://vulnuser:vuln2024secure@db:5432/vulnerabilidades"
    class Config:
        env_file = ".env"

settings = Settings()
async_url = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")
engine = create_async_engine(async_url, pool_size=10, max_overflow=20)
Session = async_sessionmaker(engine, expire_on_commit=False)

app = FastAPI(title="Vulnerabilidades GoC", version="3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

async def db():
    async with Session() as s:
        yield s

# ── Modelos ────────────────────────────────────────────────────────────────────
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

class CfgItem(BaseModel):
    nombre: str

class CfgArea(BaseModel):
    nombre: str
    subgerencia: Optional[str] = None

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
    if any(x in s for x in ['SIN','FECHA','COMPROMISO','N/A']): return None
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
    return v if v in ['PENDIENTE','EN CURSO','TERMINADA','CERRADO','RENOVACION','REVISAR'] else "PENDIENTE"

def norm_subgerencia(val):
    if not val: return None
    v = str(val).strip().replace('\n',' ')
    return v.upper() if v and v.lower() not in ('nan','none') else None

def split_detalle_obs(raw):
    if not raw: return None, None
    texto = str(raw).strip()
    patterns = [
        r'\n[Rr]esp[a-z]*\.?\s+[Oo][yY&]\s*[Mm]\s*[:.]\s*',
        r'\nRespuesta\s+[Oo]&[Mm]\s*[:.]\s*',
        r'\nRespuesta\s*[:.]\s*',
    ]
    for p in patterns:
        m = re.search(p, texto)
        if m:
            return texto[:m.start()].strip() or texto, texto[m.end():].strip() or None
    return texto, None

# ── DASHBOARD ──────────────────────────────────────────────────────────────────
@app.get("/health")
async def health(): return {"status":"ok","version":"3.0"}

@app.get("/api/dashboard")
async def dashboard(s: AsyncSession = Depends(db)):
    total       = await s.execute(text("SELECT COUNT(*) FROM vulnerabilidades"))
    estados     = await s.execute(text("SELECT estado_om, COUNT(*) FROM vulnerabilidades GROUP BY estado_om ORDER BY COUNT(*) DESC"))
    prioridades = await s.execute(text("SELECT prioridad, COUNT(*) FROM vulnerabilidades WHERE prioridad IS NOT NULL GROUP BY prioridad ORDER BY prioridad"))
    subgs       = await s.execute(text("SELECT subgerencia, COUNT(*) FROM vulnerabilidades WHERE subgerencia IS NOT NULL GROUP BY subgerencia ORDER BY COUNT(*) DESC LIMIT 10"))
    responsables= await s.execute(text("SELECT responsable_ing, COUNT(*) FROM vulnerabilidades WHERE responsable_ing IS NOT NULL GROUP BY responsable_ing ORDER BY COUNT(*) DESC LIMIT 10"))
    vencidas    = await s.execute(text("SELECT COUNT(*) FROM vulnerabilidades WHERE fecha_compromiso < NOW() AND estado_om NOT IN ('TERMINADA','CERRADO')"))
    crit_data   = await s.execute(text("SELECT prioridad, estado_om, COUNT(*) FROM vulnerabilidades WHERE prioridad IS NOT NULL GROUP BY prioridad, estado_om ORDER BY prioridad, estado_om"))
    return {
        "total": total.scalar(), "vencidas": vencidas.scalar(),
        "por_estado": [{"estado":r[0],"total":r[1]} for r in estados],
        "por_prioridad": [{"prioridad":r[0],"total":r[1]} for r in prioridades],
        "por_subgerencia": [{"subgerencia":r[0],"total":r[1]} for r in subgs],
        "por_responsable": [{"responsable":r[0],"total":r[1]} for r in responsables],
        "criticidad_estado": [{"prioridad":r[0],"estado":r[1],"total":r[2]} for r in crit_data],
    }

# ── VULNERABILIDADES ───────────────────────────────────────────────────────────
@app.get("/api/vulnerabilidades")
async def listar(
    s: AsyncSession = Depends(db),
    page: int = Query(1,ge=1), limit: int = Query(50,ge=1,le=200),
    q: Optional[str]=None, estado: Optional[str]=None,
    prioridad: Optional[int]=None, subgerencia: Optional[str]=None,
    area: Optional[str]=None, tipo: Optional[str]=None,
    responsable_ing: Optional[str]=None, sort: str="id", dir: str="asc",
):
    where, params = [], {}
    if q:
        where.append("(detalle ILIKE :q OR area ILIKE :q OR responsable_ing ILIKE :q OR subgerencia ILIKE :q OR tipo ILIKE :q)")
        params["q"] = f"%{q}%"
    if estado:   where.append("estado_om = :estado");        params["estado"] = estado
    if prioridad:where.append("prioridad = :prioridad");     params["prioridad"] = prioridad
    if subgerencia:where.append("subgerencia = :subgerencia");params["subgerencia"] = subgerencia
    if area:     where.append("area ILIKE :area");           params["area"] = f"%{area}%"
    if tipo:     where.append("tipo ILIKE :tipo");           params["tipo"] = f"%{tipo}%"
    if responsable_ing: where.append("responsable_ing ILIKE :resp"); params["resp"] = f"%{responsable_ing}%"

    w  = ("WHERE " + " AND ".join(where)) if where else ""
    safe_cols = {"id","prioridad","estado_om","subgerencia","area","tipo","fecha_declaracion","fecha_compromiso","updated_at"}
    sc = sort if sort in safe_cols else "id"
    sd = "DESC" if dir.lower()=="desc" else "ASC"
    offset = (page-1)*limit

    cnt  = await s.execute(text(f"SELECT COUNT(*) FROM vulnerabilidades {w}"), params)
    rows = await s.execute(text(f"""
        SELECT id, tipo, detalle, subgerencia, area, solicitante,
               responsable_om, responsable_ing, prioridad,
               fecha_declaracion, fecha_compromiso, fecha_solucion,
               estado_om, estado_ing, condicion_ing, updated_at
        FROM vulnerabilidades {w}
        ORDER BY {sc} {sd} LIMIT :limit OFFSET :offset
    """), {**params, "limit":limit, "offset":offset})
    return {"total":cnt.scalar(),"page":page,"limit":limit,"items":[dict(r._mapping) for r in rows]}

@app.get("/api/vulnerabilidades/{vid}")
async def obtener(vid: int, s: AsyncSession = Depends(db)):
    row = await s.execute(text("SELECT * FROM vulnerabilidades WHERE id = :id"), {"id":vid})
    r = row.fetchone()
    if not r: raise HTTPException(404,"No encontrado")
    vuln = dict(r._mapping)
    notas = await s.execute(text("SELECT * FROM notas WHERE vulnerabilidad_id = :id ORDER BY created_at DESC"), {"id":vid})
    hist  = await s.execute(text("SELECT * FROM historial WHERE vulnerabilidad_id = :id ORDER BY created_at DESC LIMIT 30"), {"id":vid})
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
    row = await s.execute(text("SELECT * FROM vulnerabilidades WHERE id = :id"), {"id":vid})
    cur = row.fetchone()
    if not cur: raise HTTPException(404,"No encontrado")
    updates = {k:v for k,v in body.model_dump(exclude_none=True).items()}
    if not updates: return {"message":"Sin cambios"}
    cur_dict = dict(cur._mapping)
    for campo, nuevo in updates.items():
        anterior = cur_dict.get(campo)
        if str(anterior) != str(nuevo):
            await s.execute(text("INSERT INTO historial (vulnerabilidad_id,campo,valor_anterior,valor_nuevo) VALUES (:id,:c,:a,:n)"),
                {"id":vid,"c":campo,"a":str(anterior),"n":str(nuevo)})
    set_sql = ", ".join(f"{k} = :{k}" for k in updates)
    await s.execute(text(f"UPDATE vulnerabilidades SET {set_sql} WHERE id = :id"), {**updates,"id":vid})
    await s.commit()
    return {"message":"OK"}

@app.delete("/api/vulnerabilidades/{vid}")
async def eliminar(vid: int, s: AsyncSession = Depends(db)):
    res = await s.execute(text("DELETE FROM vulnerabilidades WHERE id = :id RETURNING id"), {"id":vid})
    if not res.fetchone(): raise HTTPException(404,"No encontrado")
    await s.commit()
    return {"message":"Eliminado"}

@app.post("/api/vulnerabilidades/{vid}/notas", status_code=201)
async def agregar_nota(vid: int, body: NotaIn, s: AsyncSession = Depends(db)):
    row = await s.execute(text("SELECT id FROM vulnerabilidades WHERE id = :id"), {"id":vid})
    if not row.fetchone(): raise HTTPException(404,"No encontrado")
    await s.execute(text("INSERT INTO notas (vulnerabilidad_id,autor,texto) VALUES (:id,:autor,:texto)"),
        {"id":vid,"autor":body.autor,"texto":body.texto})
    await s.commit()
    return {"message":"Nota agregada"}

# ── FILTROS & CONFIGURACIÓN ────────────────────────────────────────────────────
@app.get("/api/filtros")
async def filtros(s: AsyncSession = Depends(db)):
    subgs  = await s.execute(text("SELECT nombre FROM cfg_subgerencias WHERE activo=TRUE ORDER BY nombre"))
    areas  = await s.execute(text("SELECT nombre, subgerencia FROM cfg_areas WHERE activo=TRUE ORDER BY subgerencia, nombre"))
    tipos  = await s.execute(text("SELECT nombre FROM cfg_tipos WHERE activo=TRUE ORDER BY nombre"))
    resps  = await s.execute(text("SELECT nombre FROM cfg_responsables WHERE activo=TRUE ORDER BY nombre"))
    return {
        "subgerencias": [r[0] for r in subgs],
        "areas": [{"nombre":r[0],"subgerencia":r[1]} for r in areas],
        "tipos": [r[0] for r in tipos],
        "responsables_ing": [r[0] for r in resps],
    }

# Config CRUD — Subgerencias
@app.get("/api/config/subgerencias")
async def get_subgs(s: AsyncSession = Depends(db)):
    r = await s.execute(text("SELECT id,nombre,activo FROM cfg_subgerencias ORDER BY nombre"))
    return [dict(x._mapping) for x in r]

@app.post("/api/config/subgerencias", status_code=201)
async def add_subg(body: CfgItem, s: AsyncSession = Depends(db)):
    await s.execute(text("INSERT INTO cfg_subgerencias (nombre) VALUES (:n) ON CONFLICT DO NOTHING"), {"n":body.nombre.upper()})
    await s.commit(); return {"message":"OK"}

@app.delete("/api/config/subgerencias/{id}")
async def del_subg(id: int, s: AsyncSession = Depends(db)):
    await s.execute(text("UPDATE cfg_subgerencias SET activo=FALSE WHERE id=:id"), {"id":id})
    await s.commit(); return {"message":"OK"}

# Config CRUD — Áreas
@app.get("/api/config/areas")
async def get_areas(s: AsyncSession = Depends(db)):
    r = await s.execute(text("SELECT id,nombre,subgerencia,activo FROM cfg_areas ORDER BY subgerencia,nombre"))
    return [dict(x._mapping) for x in r]

@app.post("/api/config/areas", status_code=201)
async def add_area(body: CfgArea, s: AsyncSession = Depends(db)):
    await s.execute(text("INSERT INTO cfg_areas (nombre,subgerencia) VALUES (:n,:s) ON CONFLICT DO NOTHING"),
        {"n":body.nombre,"s":body.subgerencia})
    await s.commit(); return {"message":"OK"}

@app.delete("/api/config/areas/{id}")
async def del_area(id: int, s: AsyncSession = Depends(db)):
    await s.execute(text("UPDATE cfg_areas SET activo=FALSE WHERE id=:id"), {"id":id})
    await s.commit(); return {"message":"OK"}

# Config CRUD — Tipos
@app.get("/api/config/tipos")
async def get_tipos(s: AsyncSession = Depends(db)):
    r = await s.execute(text("SELECT id,nombre,activo FROM cfg_tipos ORDER BY nombre"))
    return [dict(x._mapping) for x in r]

@app.post("/api/config/tipos", status_code=201)
async def add_tipo(body: CfgItem, s: AsyncSession = Depends(db)):
    await s.execute(text("INSERT INTO cfg_tipos (nombre) VALUES (:n) ON CONFLICT DO NOTHING"), {"n":body.nombre})
    await s.commit(); return {"message":"OK"}

@app.delete("/api/config/tipos/{id}")
async def del_tipo(id: int, s: AsyncSession = Depends(db)):
    await s.execute(text("UPDATE cfg_tipos SET activo=FALSE WHERE id=:id"), {"id":id})
    await s.commit(); return {"message":"OK"}

# Config CRUD — Responsables
@app.get("/api/config/responsables")
async def get_resps(s: AsyncSession = Depends(db)):
    r = await s.execute(text("SELECT id,nombre,activo FROM cfg_responsables ORDER BY nombre"))
    return [dict(x._mapping) for x in r]

@app.post("/api/config/responsables", status_code=201)
async def add_resp(body: CfgItem, s: AsyncSession = Depends(db)):
    await s.execute(text("INSERT INTO cfg_responsables (nombre) VALUES (:n) ON CONFLICT DO NOTHING"), {"n":body.nombre})
    await s.commit(); return {"message":"OK"}

@app.delete("/api/config/responsables/{id}")
async def del_resp(id: int, s: AsyncSession = Depends(db)):
    await s.execute(text("UPDATE cfg_responsables SET activo=FALSE WHERE id=:id"), {"id":id})
    await s.commit(); return {"message":"OK"}

# ── IMPORTAR ───────────────────────────────────────────────────────────────────
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
                    raw_det = safe(row.get("DETALLE")) or safe(row.get("TIPO"))
                    if not raw_det: skipped += 1; continue

                    detalle, obs_extra = split_detalle_obs(raw_det)
                    obs_col = safe(row.get("OBSERVACIONES O&M"))
                    obs_final = "\n\n".join(filter(None,[obs_col, obs_extra])) or None

                    resp_ing = title_case(row.get("RESPONSABLE ING"))

                    # Auto-registrar responsable si no existe
                    if resp_ing:
                        await s.execute(text(
                            "INSERT INTO cfg_responsables (nombre) VALUES (:n) ON CONFLICT DO NOTHING"
                        ), {"n": resp_ing})

                    await s.execute(text("""
                        INSERT INTO vulnerabilidades
                            (tipo,detalle,subgerencia,area,solicitante,responsable_om,responsable_ing,
                             prioridad,fecha_declaracion,fecha_compromiso,fecha_solucion,
                             estado_om,estado_ing,condicion_ing,obs_om,obs_ing)
                        VALUES
                            (:tipo,:detalle,:subgerencia,:area,:solicitante,:responsable_om,:responsable_ing,
                             :prioridad,:fecha_declaracion,:fecha_compromiso,:fecha_solucion,
                             :estado_om,:estado_ing,:condicion_ing,:obs_om,:obs_ing)
                    """), {
                        "tipo":              title_case(row.get("TIPO")) or "Vulnerabilidad",
                        "detalle":           detalle,
                        "subgerencia":       norm_subgerencia(row.get("SUBGERENCIA")),
                        "area":              title_case(row.get("AREA")),
                        "solicitante":       title_case(row.get("SOLICITANTE")),
                        "responsable_om":    title_case(row.get("RESPONSABLE")),
                        "responsable_ing":   resp_ing,
                        "prioridad":         safe_int(row.get("PRIORIDAD")),
                        "fecha_declaracion": safe_date(row.get("FECHA DECLARACION")),
                        "fecha_compromiso":  safe_date(row.get("FECHA COMPROMISO")),
                        "fecha_solucion":    safe_date(row.get("FECHA SOLUCION")),
                        "estado_om":         norm_estado(row.get("ESTADO O&M")),
                        "estado_ing":        safe(row.get("ESTADO ING")),
                        "condicion_ing":     safe(row.get("CONDICION ING")),
                        "obs_om":            obs_final,
                        "obs_ing":           safe(row.get("OBSERVACIONES ING")),
                    })
                    inserted += 1
            except Exception:
                skipped += 1; continue

        await s.commit()
        return {"inserted":inserted,"skipped":skipped}
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")
