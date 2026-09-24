const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path'); // <-- Añadido para manejar rutas de carpetas

const app = express();
app.use(cors());
app.use(express.json());

// Servir los archivos estáticos de tu frontend (carpeta public)
app.use(express.static(path.join(__dirname, 'public')));

const SECRET_KEY = "eyl_secreto_super_seguro_2026";

// Configuración de la conexión a PostgreSQL (compatible con Render y entorno local)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/eyldb',
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Inicializar la base de datos y sus tablas
async function initDB() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, nombre TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'usuario')`);
        await pool.query(`CREATE TABLE IF NOT EXISTS trabajadores (id SERIAL PRIMARY KEY, nombre TEXT, cargo TEXT, obra TEXT, estado TEXT)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS maquinaria (id SERIAL PRIMARY KEY, nombre TEXT, ubicacion TEXT, asignado TEXT, estado TEXT)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS materiales (id SERIAL PRIMARY KEY, nombre TEXT, stock INTEGER, unidad TEXT, estado TEXT)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS obras (id SERIAL PRIMARY KEY, nombre TEXT, cliente TEXT, ubicacion TEXT, estado TEXT)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS gastos (id SERIAL PRIMARY KEY, descripcion TEXT, monto INTEGER, obra TEXT, fecha TEXT)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS tareas (id SERIAL PRIMARY KEY, descripcion TEXT, responsable TEXT, estado TEXT)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS empresas_comerciales (
            id SERIAL PRIMARY KEY,
            razon_social TEXT,
            rut TEXT,
            tamano_empresa TEXT,
            actividad_economica TEXT,
            direccion TEXT,
            comuna TEXT,
            nombre_contacto TEXT,
            cargo_contacto TEXT,
            email TEXT,
            telefono TEXT
        )`);
        console.log('Conectado y tablas verificadas en PostgreSQL.');
    } catch (err) {
        console.error('Error al inicializar la base de datos:', err.message);
    }
}
initDB();

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Token requerido' });
    jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.user = decoded;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado' });
    next();
};

app.post('/auth/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Faltan datos' });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            `INSERT INTO users (nombre, email, password, role) VALUES ($1, $2, $3, 'usuario')`,
            [nombre, email, hashedPassword]
        );
        res.json({ message: 'Registrado con éxito' });
    } catch (err) {
        res.status(400).json({ error: 'Correo ya registrado o error en el servidor' });
    }
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });

        const token = jwt.sign(
            { id: user.id, nombre: user.nombre, role: user.role, email: user.email },
            SECRET_KEY,
            { expiresIn: '8h' }
        );
        res.json({ token, user: { nombre: user.nombre, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const allowedTables = ['trabajadores', 'maquinaria', 'materiales', 'obras', 'gastos', 'tareas', 'empresas_comerciales'];

app.get('/api/:table', verifyToken, async (req, res) => {
    const { table } = req.params;
    if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabla no válida' });
    try {
        const result = await pool.query(`SELECT * FROM ${table}`);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/:table/:id', verifyToken, isAdmin, async (req, res) => {
    const { table, id } = req.params;
    if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabla no válida' });
    try {
        await pool.query(`DELETE FROM ${table} WHERE id = $1`, [id]);
        res.json({ message: 'Eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/:table/:id', verifyToken, isAdmin, async (req, res) => {
    const { table, id } = req.params;
    if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabla no válida' });
    const keys = Object.keys(req.body);
    const values = Object.values(req.body);
    if (keys.length === 0) return res.json({ message: 'Sin cambios' });

    const setClause = keys.map((k, index) => `${k} = $${index + 1}`).join(', ');
    try {
        await pool.query(`UPDATE ${table} SET ${setClause} WHERE id = $${keys.length + 1}`, [...values, id]);
        res.json({ message: 'Actualizado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/trabajadores', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `INSERT INTO trabajadores (nombre, cargo, obra, estado) VALUES ($1, $2, $3, $4) RETURNING id`,
            [req.body.nombre, req.body.cargo, req.body.obra, req.body.estado]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/maquinaria', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `INSERT INTO maquinaria (nombre, ubicacion, asignado, estado) VALUES ($1, $2, $3, $4) RETURNING id`,
            [req.body.nombre, req.body.ubicacion, req.body.asignado, req.body.estado]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/materiales', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `INSERT INTO materiales (nombre, stock, unidad, estado) VALUES ($1, $2, $3, $4) RETURNING id`,
            [req.body.nombre, req.body.stock, req.body.unidad, req.body.estado]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/obras', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `INSERT INTO obras (nombre, cliente, ubicacion, estado) VALUES ($1, $2, $3, $4) RETURNING id`,
            [req.body.nombre, req.body.cliente, req.body.ubicacion, req.body.estado]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/gastos', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `INSERT INTO gastos (descripcion, monto, obra, fecha) VALUES ($1, $2, $3, $4) RETURNING id`,
            [req.body.descripcion, req.body.monto, req.body.obra, req.body.fecha]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/tareas', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `INSERT INTO tareas (descripcion, responsable, estado) VALUES ($1, $2, $3) RETURNING id`,
            [req.body.descripcion, req.body.responsable, req.body.estado]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/empresas_comerciales', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `INSERT INTO empresas_comerciales (razon_social, rut, tamano_empresa, actividad_economica, direccion, comuna, nombre_contacto, cargo_contacto, email, telefono) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`, 
            [req.body.razon_social, req.body.rut, req.body.tamano_empresa, req.body.actividad_economica, req.body.direccion, req.body.comuna, req.body.nombre_contacto, req.body.cargo_contacto, req.body.email, req.body.telefono]
        );
        res.json({ id: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Redirigir cualquier otra ruta al index.html para que cargue la interfaz web
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});