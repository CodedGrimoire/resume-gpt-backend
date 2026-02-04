require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3003;

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Rate Limiting (Load Balancer functionality)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Limit each IP to 50 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Stricter rate limit for upload endpoint
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 uploads per hour
  message: {
    error: 'Too many upload requests. Please try again later.',
    retryAfter: '1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(cors());
app.use(express.json());
app.use(limiter); // Apply rate limiting to all routes

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = 'llama-3.3-70b-versatile';

// PDF Validation Helper Functions
const isValidPDF = (buffer) => {
  // Check PDF magic bytes (file signature)
  // PDF files start with %PDF- followed by version number
  const pdfSignature = buffer.toString('ascii', 0, 4);
  return pdfSignature === '%PDF';
};

const validatePDFFile = (file) => {
  const errors = [];
  
  // Check file extension
  const ext = path.extname(file.originalname).toLowerCase();
  if (ext !== '.pdf') {
    errors.push('File must have .pdf extension');
  }
  
  // Check MIME type
  if (file.mimetype !== 'application/pdf') {
    errors.push('File must be of type application/pdf');
  }
  
  // Check file size (max 10MB)
  const maxSize = 10 * 1024 * 1024; // 10MB in bytes
  if (file.size > maxSize) {
    errors.push(`File size exceeds maximum limit of 10MB. Current size: ${(file.size / 1024 / 1024).toFixed(2)}MB`);
  }
  
  return errors;
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    // Sanitize filename to prevent path traversal
    const sanitizedName = path.basename(file.originalname).replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, Date.now() + '-' + sanitizedName);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Validate file extension and MIME type
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.pdf' || file.mimetype !== 'application/pdf') {
      return cb(new Error('Only PDF files are allowed'), false);
    }
    cb(null, true);
  }
});

app.get('/', (req, res) => {
  res.send('✅ ResumeGPT Backend (Groq Version) is Running');
});

app.post('/upload', uploadLimiter, upload.single('resume'), async (req, res) => {
  let filePath = null;
  
  try {
    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No PDF file uploaded',
        message: 'Please upload a PDF file using the "resume" field'
      });
    }

    filePath = req.file.path;

    // Additional validation
    const validationErrors = validatePDFFile(req.file);
    if (validationErrors.length > 0) {
      // Clean up uploaded file
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      return res.status(400).json({ 
        error: 'Invalid PDF file',
        details: validationErrors
      });
    }

    // Read file buffer
    const buffer = fs.readFileSync(filePath);
    
    // Validate PDF magic bytes (file signature)
    if (!isValidPDF(buffer)) {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      return res.status(400).json({ 
        error: 'Invalid PDF file',
        message: 'File does not appear to be a valid PDF. Please ensure the file is not corrupted.'
      });
    }

    // Attempt to parse PDF
    let pdfData;
    try {
      pdfData = await pdfParse(buffer);
    } catch (parseError) {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      return res.status(400).json({ 
        error: 'Failed to parse PDF',
        message: 'The PDF file appears to be corrupted or invalid. Please try with a different PDF file.'
      });
    }

    // Check if PDF has extractable text
    if (!pdfData.text || pdfData.text.trim().length === 0) {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      return res.status(400).json({ 
        error: 'PDF contains no extractable text',
        message: 'The PDF appears to be image-based or scanned. Please use a PDF with selectable text.'
      });
    }

    // Clean up uploaded file after successful validation
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    const inputText = pdfData.text.slice(0, 4000);

   const prompt = `
You are a professional resume and career reviewer with expertise in ATS (Applicant Tracking System) optimization and hiring best practices.

Given the resume below (between triple quotes), analyze it using the following comprehensive evaluation criteria and return **all of the following fields**.
If any field is unclear or unknown, say "Not Available". 

**CRITICAL FORMATTING REQUIREMENTS:**
- Provide each field EXACTLY ONCE - do not repeat any content
- Use the exact section headers provided below (e.g., "## SCORE:", "## FEEDBACK:")
- Keep responses concise and well-structured
- Do NOT duplicate information across different fields
- Use bullet points (• or -) for lists, not numbered lists
- Ensure each section is distinct and non-repetitive
- Do NOT include section headers in the content itself

Follow this exact format strictly:

## EVALUATION CRITERIA (Use these metrics to score the resume):

### 1. FORMATTING & STRUCTURE (25% of score)
- **Layout**: Clean, professional, easy to scan (1-2 pages ideal for most roles)
- **Sections**: Clear hierarchy with standard sections (Contact, Summary/Objective, Experience, Education, Skills)
- **Consistency**: Uniform fonts, spacing, bullet points, date formats
- **ATS-Friendly**: No complex tables, graphics, or unusual formatting that breaks ATS parsing
- **White Space**: Adequate margins and spacing for readability

### 2. CONTENT QUALITY (30% of score)
- **Quantifiable Achievements**: Uses numbers, percentages, metrics (e.g., "Increased sales by 25%", "Managed team of 10")
- **Action Verbs**: Strong action verbs (Led, Developed, Implemented, Optimized, etc.)
- **Relevance**: Content matches the target role and industry
- **Completeness**: All essential sections present with sufficient detail
- **Impact Focus**: Emphasizes results and achievements over duties

### 3. GRAMMAR & CLARITY (20% of score)
- **Grammar**: Zero spelling errors, proper punctuation, correct verb tenses
- **Clarity**: Clear, concise language without jargon or ambiguity
- **Conciseness**: No unnecessary words; bullet points are scannable (1-2 lines each)
- **Professional Tone**: Appropriate language for the industry

### 4. EXPERIENCE & ACHIEVEMENTS (15% of score)
- **Work History**: Relevant experience with clear progression
- **Gaps**: Any employment gaps are reasonable or explained
- **Achievements**: Demonstrates impact and value delivered
- **Relevance**: Experience aligns with target role requirements

### 5. SKILLS & QUALIFICATIONS (10% of score)
- **Technical Skills**: Relevant technical skills listed and demonstrated in experience
- **Soft Skills**: Appropriate soft skills mentioned where relevant
- **Certifications**: Relevant certifications or education listed
- **Skill Level**: Appropriate skill level indicators (if used)

## SCORING GUIDE:
- **9-10/10**: Exceptional resume - ATS-optimized, quantifiable achievements, zero errors, industry-leading format
- **7-8/10**: Strong resume - Minor improvements needed, good content with some metrics
- **5-6/10**: Average resume - Needs significant improvements in formatting, content, or clarity
- **3-4/10**: Weak resume - Major issues with structure, content quality, or errors
- **1-2/10**: Poor resume - Fundamental problems requiring complete revision

---

ROLE: <The job or role this resume is best suited for based on experience, skills, and content>

SCORE: <Score out of 10 with one decimal place (e.g., 7.5/10). Break down briefly: Formatting (X/2.5), Content (X/3.0), Grammar (X/2.0), Experience (X/1.5), Skills (X/1.0)>

FEEDBACK: <2-3 paragraph general resume feedback covering overall strengths and weaknesses, ATS compatibility, and overall impression>

ISSUES: <Specific, actionable issues found. Format as bullet points covering: formatting problems, grammar/spelling errors, content gaps, missing quantifiable metrics, ATS concerns, or clarity issues>

SUGGESTIONS: <5-7 specific, actionable improvements prioritized by impact. Include: specific metrics to add, formatting fixes, content enhancements, skill additions, or structural changes>

TECHNICAL SKILLS REQUIRED: <Technical skill set required for the identified role, prioritized by importance. Include both hard skills and tools/technologies>

SOFT SKILLS REQUIRED: <Soft skills valued for this role, prioritized by importance>

PROJECTS THAT IMPRESS RECRUITERS: <3-5 example project types or project descriptions that would stand out for this role. Include what makes them impressive>

JOB MARKET INSIGHT: <Current market insights including: demand trends, salary ranges (entry/mid/senior levels), job placement rates, geographic hotspots, remote work trends, and growth projections for this role globally>

LEARNING PATHS AND CERTIFICATIONS: <5-7 recommended learning paths, courses, certifications, or topics to improve fit for the role. Prioritize by relevance and include both free and paid options>
---

Here is the resume:
"""
${inputText}
"""
`;


    const response = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages: [
          {
            role: 'system',
            content: 'You are a helpful assistant that provides resume review and career guidance.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.7,
        max_tokens: 3000
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error(`❌ Groq API Error [${response.status}]:`, errText);
      return res.status(500).json({ error: `Groq API returned ${response.status}: ${errText}` });
    }

    const result = await response.json();
    let rawText = result?.choices?.[0]?.message?.content || '';

    // Clean and normalize the raw text
    const cleanText = (text) => {
      if (!text) return '';
      
      // Remove excessive newlines and whitespace
      text = text.replace(/\r/g, '');
      text = text.replace(/\n{3,}/g, '\n\n');
      text = text.replace(/[ \t]+/g, ' ');
      
      // Remove duplicate sections (simple heuristic)
      const lines = text.split('\n');
      const seen = new Set();
      const uniqueLines = [];
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const key = line.substring(0, 60).toLowerCase();
        
        // Skip duplicate section headers
        if (line.match(/^##?\s+[A-Z]/) && seen.has(key)) {
          continue;
        }
        
        if (line.length > 20) {
          seen.add(key);
        }
        uniqueLines.push(lines[i]);
      }
      
      return uniqueLines.join('\n').trim();
    };

    rawText = cleanText(rawText);

    // Improved extraction function with better pattern matching
    const extract = (label, alternatives = []) => {
      const labels = [label, ...alternatives];
      let bestMatch = null;
      let bestLength = 0;

      for (const searchLabel of labels) {
        // Try multiple patterns
        const patterns = [
          // Pattern 1: ## Label: content (until next ## or label:)
          new RegExp(`##?\\s*${searchLabel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:?\\s*\\n([\\s\\S]*?)(?=\\n##?\\s+[A-Z]|\\n[A-Z][A-Z ]+?:|$)`, 'i'),
          // Pattern 2: Label: content (without ##)
          new RegExp(`${searchLabel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:?\\s*\\n?([\\s\\S]*?)(?=\\n##?\\s+[A-Z]|\\n[A-Z][A-Z ]+?:|$)`, 'i')
        ];

        for (const pattern of patterns) {
          const match = rawText.match(pattern);
          if (match && match[1]) {
            let content = match[1].trim();
            
            // Remove markdown headers from content
            content = content.replace(/^##+\s*/gm, '');
            
            // Prefer longer, more complete matches
            if (content.length > bestLength && content.length > 10) {
              bestMatch = content;
              bestLength = content.length;
            }
          }
        }
      }

      if (!bestMatch) return 'Not Available';

      // Clean up the extracted content
      let cleaned = bestMatch
        .replace(/\n{3,}/g, '\n\n') // Remove excessive newlines
        .replace(/^\s+|\s+$/gm, '') // Trim each line
        .trim();

      // Remove duplicate lines within the content
      const lines = cleaned.split('\n');
      const uniqueContent = [];
      const contentSeen = new Set();
      
      for (const line of lines) {
        const normalized = line.trim().toLowerCase();
        if (normalized.length > 15 && !contentSeen.has(normalized)) {
          contentSeen.add(normalized);
          uniqueContent.push(line.trim());
        } else if (normalized.length <= 15) {
          uniqueContent.push(line.trim()); // Keep short lines (likely formatting)
        }
      }

      return uniqueContent.join('\n').trim() || 'Not Available';
    };

    // Extract with alternative label names
    const feedback = {
      role: extract('ROLE', ['TARGET JOB ROLE', 'Target Job Role']),
      score: extract('SCORE', ['Score']),
      feedback: extract('FEEDBACK', ['General Feedback', 'GENERAL FEEDBACK']),
      issues: extract('ISSUES', ['Areas for Improvement']),
      suggestions: extract('SUGGESTIONS', ['Suggested Improvements', 'Suggestions']),
      technicalSkills: extract('TECHNICAL SKILLS REQUIRED', ['Required Technical Skills', 'Technical Skills', 'TECHNICAL SKILLS']),
      softSkills: extract('SOFT SKILLS REQUIRED', ['Required Soft Skills', 'Soft Skills', 'SOFT SKILLS']),
      projects: extract('PROJECTS THAT IMPRESS RECRUITERS', ['Impressive Projects', 'Projects', 'PROJECTS']),
      marketInsight: extract('JOB MARKET INSIGHT', ['Job Market Insight', 'Market Insight', 'JOB MARKET']),
      learningPaths: extract('LEARNING PATHS AND CERTIFICATIONS', ['Learning Paths & Certifications', 'Learning Paths', 'Certifications', 'LEARNING PATHS']),
      raw: rawText // Keep raw for frontend parsing
    };

    res.json({
      message: '✅ Resume analyzed successfully',
      text: pdfData.text,
      feedback
    });

  } catch (err) {
    // Clean up file if it still exists
    if (filePath && fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (unlinkErr) {
        console.error('Failed to delete file:', unlinkErr);
      }
    }

    // Handle specific error types
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ 
          error: 'File too large',
          message: 'File size exceeds the maximum limit of 10MB'
        });
      }
      return res.status(400).json({ 
        error: 'File upload error',
        message: err.message
      });
    }

    // Handle validation errors
    if (err.message && err.message.includes('Only PDF files')) {
      return res.status(400).json({ 
        error: 'Invalid file type',
        message: 'Only PDF files are accepted'
      });
    }

    console.error('❌ Server Error:', err);
    res.status(500).json({ 
      error: 'Failed to analyze resume',
      message: 'An internal server error occurred. Please try again later.'
    });
  }
});

app.listen(PORT, () => {
  console.log(`🟢 Server running at http://localhost:${PORT}`);
});
