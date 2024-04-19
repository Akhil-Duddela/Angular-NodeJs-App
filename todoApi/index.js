const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const crypto = require('crypto');
const app = express();

const JWT_SECRET_KEY = crypto.randomBytes(32).toString('hex');
// Connect to MongoDB Atlas
mongoose.connect('mongodb+srv://AkhilLavanam:Akhil5354@userdata.r5fqnil.mongodb.net/userData', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log("Connected to MongoDB Atlas");
}).catch((error) => {
  console.error("Error connecting to MongoDB Atlas:", error);
  if (error.name === 'MongoNetworkError') {
    console.error("Make sure your MongoDB server is running and accessible.");
  } else if (error.name === 'MongoError' && error.message.includes('does not exist')) {
    console.error("The specified database does not exist. Please create it in MongoDB Atlas.");
  }
  process.exit(1); // Exit the process if unable to connect
});

app.use(cors());
app.use(bodyParser.json());

// Define the schema for user details
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    unique: true,
    match: /^\S+@\S+\.\S+$/,
    maxlength: 255
  },
  username: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    minlength: 3,
    maxlength: 30
  },
  age: {
    type: Number,
    required: true,
    min: 18
  },
  phone: {
    type: String,
    required: true,
    trim: true,
    match: /^[0-9]+$/,
    minlength: 10,
    maxlength: 15
  },
  password: {
    type: String,
    required: true,
    trim: true,
    minlength: 6,
    maxlength: 255
  }
}, { collection: 'userProfile' });



const todoSchema = new mongoose.Schema({
  username: String,
  content: String,
  timeAdded: String,
}, { collection: 'userlist' });
// Create a model based on the schema
const User = mongoose.model('User', userSchema);
const Todo = mongoose.model('Todo', todoSchema);

// Route to handle signup requests
app.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, username, age, phone, password } = req.body;
    if (!firstName || !lastName || !email || !username || !age || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (!/^[A-Za-z]+$/.test(firstName)) {
      return res.status(400).json({ message: 'First name must contain only letters' });
    }
    if (!/^[A-Za-z]+$/.test(lastName)) {
      return res.status(400).json({ message: 'Last name must contain only letters' });
    }
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    if (!/^[A-Za-z0-9]+$/.test(username)) {
      return res.status(400).json({ message: 'Username must contain only letters and numbers' });
    }
    if (isNaN(age) || age < 18) {
      return res.status(400).json({ message: 'Age must be a number and at least 18 years old' });
    }
    if (!/^[0-9]+$/.test(phone)) {
      return res.status(400).json({ message: 'Phone number must contain only numbers' });
    }
    if (phone.length < 10 || phone.length > 15) {
      return res.status(400).json({ message: 'Phone number must be between 10 and 15 digits' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    // Check if username already exists
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ firstName, lastName, email, username, age, phone, password: hashedPassword  });
   
    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error("Error creating user", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// Route to handle login requests
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Compare the hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ username: user.username }, JWT_SECRET_KEY, { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error("Error logging in", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: Missing token' });
  }
  
  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET_KEY );
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Forbidden: Invalid token' });
  }
};

app.get('/api/user/:username', verifyToken, async (req, res) => {
  try {
    const username = req.params.username;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user data", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.put('/api/user/:username', verifyToken, async (req, res) => {
  try {
    const username = req.params.username;
    const updatedUserData = req.body; // New user data to be updated

    // Find the user by username and update the details
    const updatedUser = await User.findOneAndUpdate({ username }, updatedUserData, { new: true });

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Error updating user details:", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
app.post('/api/todos', async (req, res) => {
  try {
    const { username, content } = req.body;
    const timeAdded = new Date().toLocaleString();
    const newTodo = new Todo({
      username,
      content,
      timeAdded
    });
    await newTodo.save();
    res.status(201).json({ message: 'Todo added successfully', todo: newTodo });
  } catch (error) {
    console.error('Error adding todo:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/todos/:username', verifyToken, async (req, res) => {
  try {
    const username = req.params.username;
    const todos = await Todo.find({ username });

    if (!todos) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(todos);
  } catch (error) {
    console.error("Error fetching user data", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// PUT update a todo
app.put('/api/todos/:id', verifyToken, async (req, res) => {
  try {
    const todoId = req.params.id;
    const updatedTodoData = req.body; // New todo data to be updated

    // Find the todo by its ID and update the details
    const updatedTodo = await Todo.findOneAndUpdate({ _id: todoId }, updatedTodoData, { new: true });

    if (!updatedTodo) {
      return res.status(404).json({ message: 'Todo not found' });
    }

    res.status(200).json(updatedTodo);
  } catch (error) {
    console.error("Error updating todo details:", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// DELETE a todo
app.delete('/api/todos/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const deletedTodo = await Todo.findByIdAndDelete(id);
    if (!deletedTodo) {
      return res.status(404).json({ message: 'Todo not found' });
    }
    res.status(200).json({ message: 'Todo deleted successfully', todo: deletedTodo });
  } catch (error) {
    console.error('Error deleting todo:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



const PORT = process.env.PORT || 5354;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
