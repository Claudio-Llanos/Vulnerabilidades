-- Vulnerabilidades GoC v2 — Schema limpio

CREATE TABLE IF NOT EXISTS vulnerabilidades (
    id              SERIAL PRIMARY KEY,
    tipo            VARCHAR(100) DEFAULT 'VULNERABILIDAD',
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

-- Índices
CREATE INDEX IF NOT EXISTS idx_vuln_estado   ON vulnerabilidades(estado_om);
CREATE INDEX IF NOT EXISTS idx_vuln_prioridad ON vulnerabilidades(prioridad);
CREATE INDEX IF NOT EXISTS idx_vuln_subg     ON vulnerabilidades(subgerencia);
CREATE INDEX IF NOT EXISTS idx_notas_vuln    ON notas(vulnerabilidad_id);
CREATE INDEX IF NOT EXISTS idx_hist_vuln     ON historial(vulnerabilidad_id);

-- Auto updated_at
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_vuln_updated
    BEFORE UPDATE ON vulnerabilidades
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
