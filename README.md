# Vulnerabilidades GoC v2 — Deploy

## Requisitos en la VM
- Ubuntu 20.04+
- Docker + Docker Compose instalados
- Puerto 80 abierto

---

## Paso 1 — Subir el proyecto al servidor

Desde tu máquina:
```bash
scp vuln-app.tar.gz usuario@IP_VM:/home/usuario/
```

En el servidor:
```bash
tar -xzf vuln-app.tar.gz
cd vuln-app
```

## Paso 2 — Configurar contraseña de BD

```bash
cp .env.example .env
nano .env
# Cambia DB_PASSWORD por algo seguro
```

## Paso 3 — Levantar todo

```bash
docker-compose up -d --build
```

Primera vez tarda 3-5 minutos. Luego:

```bash
docker-compose ps        # todos deben estar "Up"
curl localhost/health    # debe responder {"status":"ok"}
```

Abre en el navegador: **http://IP_VM**

---

## Paso 4 — Importar el Excel

1. Entra a la sección **Importar Excel**
2. Arrastra el archivo `.xls`
3. Listo — los datos quedan en PostgreSQL

---

## Comandos útiles

```bash
# Ver logs
docker-compose logs -f backend

# Reiniciar
docker-compose restart backend

# Detener
docker-compose down

# Backup de la BD
docker exec vuln_db pg_dump -U vulnuser vulnerabilidades > backup.sql

# Restaurar
cat backup.sql | docker exec -i vuln_db psql -U vulnuser vulnerabilidades
```

---

## Estructura

```
vuln-app/
├── docker-compose.yml
├── .env.example
├── db/init.sql          ← Schema PostgreSQL
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py          ← API FastAPI
├── frontend/
│   ├── Dockerfile
│   └── index.html       ← Web
└── nginx/nginx.conf     ← Proxy
```

## API

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | /api/dashboard | KPIs y gráficos |
| GET | /api/vulnerabilidades | Listar con filtros |
| GET | /api/vulnerabilidades/:id | Detalle + notas + historial |
| POST | /api/vulnerabilidades | Crear |
| PATCH | /api/vulnerabilidades/:id | Editar |
| DELETE | /api/vulnerabilidades/:id | Eliminar |
| POST | /api/vulnerabilidades/:id/notas | Agregar nota |
| POST | /api/importar | Importar Excel |
| GET | /api/filtros | Opciones para filtros |
