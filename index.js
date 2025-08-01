import express from "express";
import bodyParser from "body-parser";
import mysql2 from "mysql2/promise";
import dotenv from "dotenv";
import crypto from "crypto";
import https from "https";
import fs from "fs/promises";
import path from "path";
import { parse } from "csv-parse/sync";
import { fileURLToPath } from 'url';

dotenv.config();

const app = express();
const PORT = 4000;
app.use(bodyParser.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let db;

// CISA-KEV download link 
const KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv";

// Async connection establishment
const connectDB = async () => {
  try {
    db = await mysql2.createConnection({
      host: process.env.INTERNAL_HOST,
      user: process.env.USER,
      password: process.env.PW,
      database: process.env.DB,
    });
    console.log('Database connected successfully');
    await createApiKeyTable();
  } catch (error) {
    console.error('Database connection failed:', error);
    process.exit(1);
  }
};

// Create API keys table if it doesn't exist
const createApiKeyTable = async () => {
  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS api_keys (
      id INT AUTO_INCREMENT PRIMARY KEY,
      api_key VARCHAR(64) NOT NULL UNIQUE,
      app_name VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_used TIMESTAMP NULL,
      is_active BOOLEAN DEFAULT TRUE
      )
    `);
  } catch (error) {
    console.error('Error creating API keys table:', error);
  }
};

// Download CSV from CISA website
const downloadCSV = async () => {
  return new Promise((resolve, reject) => {
    const tempDir = path.join(__dirname, 'temp');
    const filePath = path.join(tempDir, 'kev_catalog.csv');
    
    https.get(KEV_URL, (response) => {
      let csvData = '';
      
      response.on('data', (chunk) => {
        csvData += chunk;
      });
      
      response.on('end', async () => {
        try {
          // Ensure temp directory exists
          await fs.mkdir(tempDir, { recursive: true });
          
          // Write the CSV data to file
          await fs.writeFile(filePath, csvData, 'utf-8');
          
          console.log(`KEV file downloaded successfully`);
          resolve(filePath);
        } catch (error) {
          reject(error);
        }
      });
      
      response.on('error', (error) => {
        reject(error);
      });
    }).on('error', (error) => {
      reject(error);
    });
  });
};

// Determine SQL data type based on sample data
const getDataType = (sampleValue) => {
  if (!sampleValue || sampleValue.trim() === '') return 'TEXT';
  
  // Integer
  if (/^\d+$/.test(sampleValue.trim())) {
    return 'INT';
  }
  
  // Float
  if (/^\d*\.\d+$/.test(sampleValue.trim())) {
    return 'FLOAT';
  }
  
  return 'TEXT';
};

// Update KEV table from CSV
const updateKEVCatalogFromCSV = async () => {
  try {
    const filePath = await downloadCSV();
    
    const csvContent = await fs.readFile(filePath, 'utf-8');
    const records = parse(csvContent, {
      columns: true,
      skip_empty_lines: true,
      trim: true
    });
    
    if (records.length === 0) {
      throw new Error("No data found in CSV file");
    }
    
    const headers = Object.keys(records[0]);
    
    let createTableQuery = "CREATE TABLE IF NOT EXISTS KEV_Catalog (";
    headers.forEach((header, index) => {
      const dataType = getDataType(records[0][header]);
      createTableQuery += `\`${header}\` ${dataType}`;
      if (index < headers.length - 1) createTableQuery += ", ";
    });
    createTableQuery += ");";
    
    await db.execute(createTableQuery);
    console.log("KEV table structure updated successfully.");
    
    await db.execute("TRUNCATE TABLE KEV_Catalog");
    
    const placeholders = headers.map(() => '?').join(', ');
    const columnNames = headers.map(h => `\`${h}\``).join(', ');
    const insertQuery = `INSERT INTO KEV_Catalog (${columnNames}) VALUES (${placeholders})`;
    
    for (const record of records) {
      const values = headers.map(header => record[header] || null);
      await db.execute(insertQuery, values);
    }
    
    await fs.unlink(filePath).catch(() => {});
    
    console.log(`KEV catalog updated successfully. Total records: ${records.length}`);
    return { success: true, recordCount: records.length };
    
  } catch (error) {
    console.error('Error updating KEV catalog:', error);
    throw error;
  }
};

// Verify API key
const verifyApiKey = async (req, res, next) => {
  const apiKey = req.header('x-api-key') || req.query.api_key;
  const appName = req.header('app-name') || req.query.app_name || req.body.app_name;
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key is required' });
  }
  
  try {
    const [rows] = await db.execute(
      'SELECT * FROM api_keys WHERE api_key = ? AND is_active = TRUE AND app_name = ?',
      [apiKey, appName]
    );
    
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
        
    // Update last_used timestamp
    await db.execute(
      'UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE api_key = ? AND app_name = ?',
      [apiKey, appName]
    );
    
    req.application = rows[0];
    next();
  } catch (error) {
    return res.status(500).json({ error: 'Failed to authenticate API key' });
  }
};

// Generate a new API key
const generateApiKey = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Initialize connection before starting server
const startServer = async () => {
    await connectDB();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
};
  
startServer();

// Create new API key
app.post("/api-keys", async (req, res) => {
  try {
    const appName = req.headers['app-name'];
    
    const apiKey = generateApiKey();
    
    await db.execute(
      'INSERT INTO api_keys (api_key, app_name) VALUES (?, ?)',
      [apiKey, appName]
    );
    
    res.status(201).json({ 
      app_name: appName,
      apiKey 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Manually download KEV data and update the KEV catalog
app.post("/update-kev", verifyApiKey, async (req, res) => {
  try {
    const result = await updateKEVCatalogFromCSV();
    res.json({
      message: "KEV catalog updated successfully",
      recordCount: result.recordCount
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all cveIDs from database
app.get("/cve", verifyApiKey, async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT cveID FROM KEV_Catalog");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all records from KEV database
app.get("/", verifyApiKey, async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM KEV_Catalog");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get number of records in database
app.get("/count", verifyApiKey, async (req, res) => {
    try {
      const [rows] = await db.execute("SELECT COUNT(cveID) as count FROM KEV_Catalog");
      res.json(rows);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
});

// Get record by cveID
app.get("/cve/:cveID", verifyApiKey, async (req, res) => {
    try {
      const [rows] = await db.execute("SELECT * FROM KEV_Catalog WHERE cveID = ?", [req.params.cveID]);
      res.json(rows);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
});

// Get all records from a specific vendor
app.get("/:vendor", verifyApiKey, async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM KEV_Catalog WHERE LOWER(vendorProject) = LOWER(?)", [req.params.vendor]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});