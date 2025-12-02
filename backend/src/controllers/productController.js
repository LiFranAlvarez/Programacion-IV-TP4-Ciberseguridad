const { db } = require('../config/database');
const mysql = require('mysql2');

// VULNERABLE: SQL Injection
const getProducts = (req, res) => {
  const { category, search } = req.query;

  if (category && /['"()=;#-]/.test(category)) {
    return res.status(200).json([]); 
  }
  if (search && /['"()=;#-]/.test(search)) {
    return res.status(200).json([]);
  }

  // VULNERABLE: Concatenación directa de strings en SQL
  let query = 'SELECT * FROM products WHERE 1=1';
  const params = [];
  
  if (category) {
    query += ` AND category = '${category}'`;
    params.push(category);
  }
  
  if (search) {
    query += ` AND name LIKE '%${search}%'`;
    params.push(`%${search}%`);
  }
  
  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
};

module.exports = {
  getProducts
};
