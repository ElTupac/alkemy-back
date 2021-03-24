const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const ROUND_SALTS = process.env.ROUND_SALTS || 10;
const PRIVATE_KEY = process.env.PRIVATE_KEY || 'que onda jorge';
const { Pool } = require('pg');
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

const getUserOperations = (req, res) => {
    const token = req.header('authorization');
    if(!token) return res.status(400).json({ok: false, error: 'NO TOKEN PROVIDED'});
    else {
        const check = verifyToken(token);
        if(check?.ok){
            const { email, name } = check.user;
            pool.query('SELECT id FROM users WHERE email = $1', [email], (err, result) => {
                if(result.rowCount){
                    const { id } = result.rows[0];
                    pool.query('SELECT * FROM operations WHERE creator_id = $1 ORDER BY date_done DESC LIMIT 10', [id], (err, result) => {
                        if(!err){
                            return res.status(200).json({ok: true, operations: result.rows});
                        }else{
                            return res.status(500).json({ok: false, error: 'INTERNAL SERVER ERROR'});
                        }
                    })
                }else{
                    return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
                }
            })
        }else{
            return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
        }
    }
}

const createUserOperation = (req, res) => {
    const token = req.header('authorization');
    const { mount, concept, date_done, op_type, category } = req.body;
    if(!token) return res.status(400).json({ok: false, error: 'NO TOKEN PROVIDED'});
    if(!mount || !concept || !date_done || (op_type !== 'INGRESO' && op_type !== 'EGRESO') || !category) return res.status(400).json({ok: false, error: 'NOT ENOUGH PROPERTIES'});
    else {
        const check = verifyToken(token);
        if(check?.ok){
            const { email, name } = check.user;
            pool.query('SELECT id FROM users WHERE email = $1', [email], (err, result) => {
                if(result.rowCount){
                    const { id } = result.rows[0];
                    pool.query('INSERT INTO operations (concept, mount, date_done, op_type, category, creator_id) VALUES ($1, $2, $3, $4, $5, $6)', 
                        [concept, mount, date_done, op_type, category, id],
                        (err, result) => {
                            if(!err){
                                return res.status(201).json({ok: true, operation: req.body});
                            }else{
                                return res.status(500).json({ok: false, error: 'INTERNAL SERVER ERROR'});
                            }
                        }
                    );
                }else{
                    return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
                }
            })
        }else{
            return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
        }
    }
}

const updateUserOperation = (req, res) => {
    const token = req.header('authorization');
    const { mount, concept, category, op_id } = req.body;
    if(!mount && !concept && !category || !op_id) return res.status(400).json({ok: false, error: 'NO PROVIDED VALID FIELDS'});
    if(!token) return res.status(400).json({ok: false, error: 'NO TOKEN PROVIDED'});
    else {
        const check = verifyToken(token);
        if(check?.ok){
            const { email, name } = check.user;
            pool.query('SELECT id FROM users WHERE email = $1', [email], (err, result) => {
                if(result.rowCount){
                    const { id } = result.rows[0];
                    let updates = [];
                    if(mount) updates.push(`mount = ${mount}`);
                    if(concept) updates.push(`concept = '${concept}'`);
                    if(category) updates.push(`category = '${category}'`);
                    updates = updates.join(', ');
                    pool.query(`UPDATE operations SET ${updates} WHERE id = $1 AND creator_id = $2`, [op_id, id], (err, result) => {
                        if(!err){
                            return res.status(200).json({ok: true});
                        }else{
                            return res.status(500).json({ok: false, error: 'INTERNAL SERVER ERROR'});
                        }
                    });
                }else{
                    return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
                }
            })
        }else{
            return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
        }
    }
}

const deleteUserOperation = (req, res) => {
    const token = req.header('authorization');
    const { op_id } = req.body;
    if(!op_id) return res.status(400).json({ok: false, error: 'NO VALID OPERATION ID'});
    if(!token) return res.status(400).json({ok: false, error: 'NO TOKEN PROVIDED'});
    else {
        const check = verifyToken(token);
        if(check?.ok){
            const { email, name } = check.user;
            pool.query('SELECT id FROM users WHERE email = $1', [email], (err, result) => {
                if(result.rowCount){
                    const { id } = result.rows[0];
                    pool.query('DELETE FROM operations WHERE creator_id = $1 AND id = $2', [id, op_id], (err, result) => {
                        if(!err){
                            return res.status(200).json({ok: true});
                        }else{
                            return res.status(500).json({ok: false, error: 'INTERNAL SERVER ERROR'});
                        }
                    })
                }else{
                    return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
                }
            })
        }else{
            return res.status(400).json({ok: false, error: 'BAD TOKEN PROVIDED'});
        }
    }
}

const loginUser = (req, res) => {
    const { email, password } = req.body;
    if(!email || !password) return res.status(400).json({ok: false, error: 'NOT ENOUGH PROPERTIES'});
    pool.query('SELECT name, email, password FROM users WHERE email = $1', [email], (err, result) => {
        if(result.rowCount){
            const hashed = result.rows[0].password;
            const username = result.rows[0].name;
            bcrypt.compare(password, hashed, (err, result) => {
                if(result) {
                    const token = generateToken(email, username);
                    if(token){
                        return res.status(200).json({ok: true, user: {email, token}})
                    }else{
                        return res.status(500).json({ok: false, error: 'INTERNAL ERROR WHEN GENERATING TOKEN'});
                    }
                } else return res.status(400).json({ok: false, error: 'BAD CREDENTIALS'});
            });
        }else{
            return res.status(400).json({ok: false, error: 'BAD CREDENTIALS'});
        }
    });
}

const registerUser = (req, res) => {
    const { email, name, password } = req.body;
    if(!email || !name || !password) return res.status(400).json({ok: false, error: 'NOT ENOUGH PROPERTIES'});
    pool.query('SELECT name, email FROM users WHERE email = $1', [email], (error, results) => {
        if(!results.rowCount){
            bcrypt.hash(password, ROUND_SALTS, (err, hash) => {
                if(hash){
                    pool.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3)', [name, email, hash], (err, result) => {
                        if(err){
                            return res.status(500).json({ok: false, error: 'USER NOT CREATED'});
                        }else{
                            return res.status(201).json({ok: true, user: {email, name}});
                        }
                    })
                }else{
                    return res.status(500).json({ok: false, error: 'USER NOT CREATED'});
                }
            })
        }else{
            return res.status(400).json({ok: false, error: 'EMAIL USED'});
        }
    });
}

const checkToken = (req, res) => {
    const { email } = req.body;
    const token = req.header('authorization');
    if(!token) return res.status(400).json({ok: false, error: 'NO TOKEN PROVIDED'});
    if(!email) return res.status(400).json({ok: false, error: 'NO EMAIL PROVIDED'});
    const check = verifyToken(token);
    if(check?.ok && check?.user.email === email){
        console.log(check.user.name, check.user.email)
        return res.status(200).json({ok: true, user: {email, name: check.user.name, token: generateToken(email, check.user.name)}})
    }else return res.status(400).json({ok: false, error: 'BAD TOKEN'});
}

function verifyToken(token){
    try {
        const decoded = jwt.verify(token, PRIVATE_KEY);
        if(decoded) return {ok: true, user: {email: decoded.email, name: decoded.name}};
        else return {ok: false};
    } catch (error) {
        return {ok: false};
    }
}

function generateToken(email, name){
    return jwt.sign({email, name}, PRIVATE_KEY, {expiresIn: '1h'});
}

module.exports = {
    getUserOperations,
    createUserOperation,
    updateUserOperation,
    deleteUserOperation,
    loginUser,
    registerUser,
    checkToken
}