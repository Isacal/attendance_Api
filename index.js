const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false })); 
app.use(bodyParser.json()); 
app.use(express.json());
const port = 4000; // Adjust port number as needed

// Database credentials
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'student_attendance'
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Unauthorized access: Token missing');
  jwt.verify(token.replace('Bearer ', ''), 'Isacal', (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).send('Unauthorized access: Invalid or expired token');
    }
    req.userId = decoded.id;
    next();
  });
};

// Get all data from a students table
app.get('/students',verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM students');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving students');
  }
});

// Select Single student
app.get('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.query('SELECT * FROM students WHERE stud_id = ?', [id]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error showing students');
  }
});

// Insert data into students table
app.post('/students', verifyToken, async (req, res) => {
  const { inst_id, reg_no, name, created_at, updated_at, created_by, updated_by, usr_id, mod_id } = req.body; // Destructure data from request body
  if (!inst_id || !reg_no || !name || !created_at || !updated_at || !created_by || !updated_by || !usr_id || !mod_id) {
    return res.status(400).send('Please provide all required fields (email,password)');
  }
  try {
    const [result] = await pool.query('INSERT INTO students SET ?', { inst_id, reg_no, name, created_at, updated_at, created_by, updated_by, usr_id, mod_id });
    res.json({ message: `students inserted successfully with ID: ${result.insertId}` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error inserting role');
  }
});

// Update student
app.put('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const { inst_id, reg_no, name, created_at, updated_at, created_by, updated_by, usr_id, mod_id } = req.body; // Destructure data from request body
  if (!inst_id || !reg_no || !name || !created_at || !updated_at || !created_by || !updated_by || !usr_id || !mod_id) {
    return res.status(400).send('Please provide all required fields');
  }
  try {
    const [result] = await pool.query('UPDATE students SET inst_id=?, reg_no=?, name=?, created_at=?, updated_at=?, created_by=?, updated_by=?, usr_id=?, mod_id=? WHERE stud_id = ?', [inst_id, reg_no, name, created_at, updated_at, created_by, updated_by, usr_id, mod_id,id ]);
    res.json({ message: `student data updated successfully with ID: ${req.params.id}` });  // Use ID from request params
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating student');
  }
});

// PATCH route to partially update reg_no and name of an existing student
app.patch('/students/:id', verifyToken, async (req, res) => {
  const studentId = req.params.id;
  const { reg_no, name } = req.body; // Destructure reg_no and name from request body
  if (!reg_no && !name) {
      return res.status(400).send('Please provide at least one field to update (reg_no or name)');
  }
  try {
      let updateData = {};
      if (reg_no) updateData.reg_no = reg_no;
      if (name) updateData.name = name;
      const [result] = await pool.query('UPDATE students SET ? WHERE stud_id=?', [updateData, studentId]);
      if (result.affectedRows === 0) {
          res.status(404).json({ message: 'Student not found' });
      } else {
          res.status(200).json({ message: 'Student updated successfully' });
      }
  } catch (err) {
      console.error(err);
      res.status(500).send('Error updating student');
  }
});


// Delete student by ID
app.delete('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM students WHERE stud_id = ?', [id]);
    res.json({ message: `student with ID ${id} deleted successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting role');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { userName,password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE userName = ?', [userName]);
    if (!users.length) {
      return res.status(404).send('User not found');
    }

    const user = users[0];
    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Invalid password');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id }, 'Isacal', { expiresIn: '1h' });

    // Send the token as response
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
