require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use('/styles', express.static(path.join(__dirname, '../styles')));
app.use('/js', express.static(path.join(__dirname, '../js')));
app.use('/public', express.static(path.join(__dirname, '../public')));

// Test route
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Basic serverless function working',
    timestamp: new Date().toISOString()
  });
});

// Serve static HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../login.html'));
});

// Catch all handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Export for serverless
module.exports = (req, res) => {
  app(req, res);
};
