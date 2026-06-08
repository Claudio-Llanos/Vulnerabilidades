-- Vulnerabilidades GoC v3 — Schema con listas controladas

CREATE TABLE IF NOT EXISTS vulnerabilidades (
    id              SERIAL PRIMARY KEY,
    tipo            VARCHAR(100) DEFAULT 'Vulnerabilidad',
    detalle         TEXT NOT NULL,
    subgerencia     VARCHAR(200),
    area            VARCHAR(200),
    solicitante     VARCHAR(200),
    responsable_om  VARCHAR(200),
    responsable_ing VARCHAR(200),
    prioridad       SMALLINT CHECK (prioridad IN (1,2,3)) DEFAULT 1,
    fecha_declaracion DATE,
    fecha_compromiso  DATE,
    fecha_solucion    DATE,
    estado_om       VARCHAR(50) DEFAULT 'PENDIENTE'
                    CHECK (estado_om IN ('PENDIENTE','EN CURSO','TERMINADA','CERRADO','RENOVACION','REVISAR')),
    estado_ing      VARCHAR(100),
    condicion_ing   VARCHAR(300),
    obs_om          TEXT,
    obs_ing         TEXT,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notas (
    id                   SERIAL PRIMARY KEY,
    vulnerabilidad_id    INTEGER REFERENCES vulnerabilidades(id) ON DELETE CASCADE,
    autor                VARCHAR(100) DEFAULT 'Usuario',
    texto                TEXT NOT NULL,
    created_at           TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS historial (
    id                   SERIAL PRIMARY KEY,
    vulnerabilidad_id    INTEGER REFERENCES vulnerabilidades(id) ON DELETE CASCADE,
    campo                VARCHAR(100),
    valor_anterior       TEXT,
    valor_nuevo          TEXT,
    usuario              VARCHAR(100) DEFAULT 'Usuario',
    created_at           TIMESTAMP DEFAULT NOW()
);

-- Listas controladas
CREATE TABLE IF NOT EXISTS cfg_subgerencias (
    id      SERIAL PRIMARY KEY,
    nombre  VARCHAR(200) UNIQUE NOT NULL,
    activo  BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS cfg_areas (
    id              SERIAL PRIMARY KEY,
    nombre          VARCHAR(200) NOT NULL,
    subgerencia     VARCHAR(200),
    activo          BOOLEAN DEFAULT TRUE,
    UNIQUE(nombre, subgerencia)
);

CREATE TABLE IF NOT EXISTS cfg_tipos (
    id      SERIAL PRIMARY KEY,
    nombre  VARCHAR(200) UNIQUE NOT NULL,
    activo  BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS cfg_responsables (
    id      SERIAL PRIMARY KEY,
    nombre  VARCHAR(200) UNIQUE NOT NULL,
    activo  BOOLEAN DEFAULT TRUE
);

-- Índices
CREATE INDEX IF NOT EXISTS idx_vuln_estado    ON vulnerabilidades(estado_om);
CREATE INDEX IF NOT EXISTS idx_vuln_prioridad ON vulnerabilidades(prioridad);
CREATE INDEX IF NOT EXISTS idx_vuln_subg      ON vulnerabilidades(subgerencia);
CREATE INDEX IF NOT EXISTS idx_vuln_area      ON vulnerabilidades(area);
CREATE INDEX IF NOT EXISTS idx_notas_vuln     ON notas(vulnerabilidad_id);
CREATE INDEX IF NOT EXISTS idx_hist_vuln      ON historial(vulnerabilidad_id);

-- Auto updated_at
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_vuln_updated
    BEFORE UPDATE ON vulnerabilidades
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Datos iniciales — Subgerencias
INSERT INTO cfg_subgerencias (nombre) VALUES
  ('INFRAESTRUCTURA REDES IP'),
  ('OPERACION SERVICIOS DE TV&VIDEO'),
  ('PREPAGO Y SVA'),
  ('OPERACION REDES TX Y BACKHAUL'),
  ('VNF OP. MOVIL & TELEFONIA FIJA -ROAMING'),
  ('INFRAESTRUCTURA TECNOLOGICA Y DEVOPS'),
  ('OPERACION PREPAGO Y SVA MOVIL')
ON CONFLICT DO NOTHING;

-- Datos iniciales — Áreas
INSERT INTO cfg_areas (nombre, subgerencia) VALUES
  ('Servicios',           'INFRAESTRUCTURA REDES IP'),
  ('Seguridad',           'INFRAESTRUCTURA REDES IP'),
  ('MPLS & ISP',          'INFRAESTRUCTURA REDES IP'),
  ('TX Backhaul',         'OPERACION REDES TX Y BACKHAUL'),
  ('Prepago',             'PREPAGO Y SVA'),
  ('SVA Movil',           'OPERACION PREPAGO Y SVA MOVIL'),
  ('TV & Video',          'OPERACION SERVICIOS DE TV&VIDEO'),
  ('DevOps',              'INFRAESTRUCTURA TECNOLOGICA Y DEVOPS'),
  ('VNF',                 'VNF OP. MOVIL & TELEFONIA FIJA -ROAMING')
ON CONFLICT DO NOTHING;

-- Datos iniciales — Tipos
INSERT INTO cfg_tipos (nombre) VALUES
  ('Sin Redundancia Geográfica'),
  ('Sin Redundancia Local'),
  ('Hardware Obsoleto'),
  ('Software Obsoleto'),
  ('Hardware | Software'),
  ('Salida De Sitio'),
  ('Conexión Energía'),
  ('Alta Disponibilidad Local'),
  ('Alta Disponibilidad Geográfica'),
  ('Tráfico'),
  ('Fuera De Soporte HW Y FW (EOX)'),
  ('Equipos Sin AAA'),
  ('Seguridad'),
  ('Vulnerabilidad')
ON CONFLICT DO NOTHING;

-- Datos iniciales — Responsables ING
INSERT INTO cfg_responsables (nombre) VALUES
  ('Hernan Fuentes'),
  ('Mauricio Vidal'),
  ('Ortega'),
  ('Morales'),
  ('David Ortega'),
  ('H. Lopez'),
  ('Mario Ramirez'),
  ('Victor Betancourt')
ON CONFLICT DO NOTHING;
