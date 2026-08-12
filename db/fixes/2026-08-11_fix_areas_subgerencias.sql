-- Fix: corregir nombres de subgerencia en cfg_areas para que coincidan
-- con cfg_subgerencias, y agregar area faltante para VNF.
-- Aplicado: 2026-08-11

UPDATE cfg_areas SET subgerencia = 'SVA MOVIL Y ROAMING' WHERE subgerencia = 'SVA MOVIL & ROAMING';
INSERT INTO cfg_areas (nombre, subgerencia) VALUES ('VNF', 'VNF OP. MOVIL & TELEFONIA FIJA -ROAMING')
ON CONFLICT DO NOTHING;
