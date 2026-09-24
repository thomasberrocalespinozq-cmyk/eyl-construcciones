const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = "eyl_secreto_super_seguro_2026";

const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error(err.message);
    console.log('Conectado a la base de datos SQLite.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'usuario')`);
    db.run(`CREATE TABLE IF NOT EXISTS trabajadores (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, cargo TEXT, obra TEXT, estado TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS maquinaria (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, ubicacion TEXT, asignado TEXT, estado TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS materiales (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, stock INTEGER, unidad TEXT, estado TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS obras (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, cliente TEXT, ubicacion TEXT, estado TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS gastos (id INTEGER PRIMARY KEY AUTOINCREMENT, descripcion TEXT, monto INTEGER, obra TEXT, fecha TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS tareas (id INTEGER PRIMARY KEY AUTOINCREMENT, descripcion TEXT, responsable TEXT, estado TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS empresas_comerciales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
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
});

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
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (nombre, email, password, role) VALUES (?, ?, ?, 'usuario')`, [nombre, email, hashedPassword], function(err) {
        if (err) return res.status(400).json({ error: 'Correo registrado' });
        res.json({ message: 'Registrado con éxito' });
    });
});

app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Credenciales incorrectas' });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });
        const token = jwt.sign({ id: user.id, nombre: user.nombre, role: user.role, email: user.email }, SECRET_KEY, { expiresIn: '8h' });
        res.json({ token, user: { nombre: user.nombre, email: user.email, role: user.role } });
    });
});

const allowedTables = ['trabajadores', 'maquinaria', 'materiales', 'obras', 'gastos', 'tareas', 'empresas_comerciales'];

app.get('/api/:table', verifyToken, (req, res) => {
    if (!allowedTables.includes(req.params.table)) return res.status(400).json({ error: 'Tabla no válida' });
    db.all(`SELECT * FROM ${req.params.table}`, [], (err, rows) => res.json(rows));
});

app.delete('/api/:table/:id', verifyToken, isAdmin, (req, res) => {
    if (!allowedTables.includes(req.params.table)) return res.status(400).json({ error: 'Tabla no válida' });
    db.run(`DELETE FROM ${req.params.table} WHERE id = ?`, req.params.id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Eliminado' });
    });
});

app.put('/api/:table/:id', verifyToken, isAdmin, (req, res) => {
    const { table, id } = req.params;
    if (!allowedTables.includes(table)) return res.status(400).json({ error: 'Tabla no válida' });
    const keys = Object.keys(req.body);
    const values = Object.values(req.body);
    if (keys.length === 0) return res.json({ message: 'Sin cambios' });
    const setClause = keys.map(k => `${k} = ?`).join(', ');
    db.run(`UPDATE ${table} SET ${setClause} WHERE id = ?`, [...values, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Actualizado' });
    });
});

app.post('/api/trabajadores', verifyToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO trabajadores (nombre, cargo, obra, estado) VALUES (?, ?, ?, ?)`, [req.body.nombre, req.body.cargo, req.body.obra, req.body.estado], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ id: this.lastID });
    });
});
app.post('/api/maquinaria', verifyToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO maquinaria (nombre, ubicacion, asignado, estado) VALUES (?, ?, ?, ?)`, [req.body.nombre, req.body.ubicacion, req.body.asignado, req.body.estado], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ id: this.lastID });
    });
});
app.post('/api/materiales', verifyToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO materiales (nombre, stock, unidad, estado) VALUES (?, ?, ?, ?)`, [req.body.nombre, req.body.stock, req.body.unidad, req.body.estado], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ id: this.lastID });
    });
});
app.post('/api/obras', verifyToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO obras (nombre, cliente, ubicacion, estado) VALUES (?, ?, ?, ?)`, [req.body.nombre, req.body.cliente, req.body.ubicacion, req.body.estado], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ id: this.lastID });
    });
});
app.post('/api/gastos', verifyToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO gastos (descripcion, monto, obra, fecha) VALUES (?, ?, ?, ?)`, [req.body.descripcion, req.body.monto, req.body.obra, req.body.fecha], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ id: this.lastID });
    });
});
app.post('/api/tareas', verifyToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO tareas (descripcion, responsable, estado) VALUES (?, ?, ?)`, [req.body.descripcion, req.body.responsable, req.body.estado], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ id: this.lastID });
    });
});
app.post('/api/empresas_comerciales', verifyToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO empresas_comerciales (razon_social, rut, tamano_empresa, actividad_economica, direccion, comuna, nombre_contacto, cargo_contacto, email, telefono) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
    [req.body.razon_social, req.body.rut, req.body.tamano_empresa, req.body.actividad_economica, req.body.direccion, req.body.comuna, req.body.nombre_contacto, req.body.cargo_contacto, req.body.email, req.body.telefono], function(err) {
        if (err) return res.status(500).json({ error: err.message }); res.json({ id: this.lastID });
    });
});

app.listen(5000, () => console.log('Backend ejecutándose en puerto 5000'));