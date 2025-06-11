require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const fs = require('fs');
const fetch = require('node-fetch');

const app = express();
const PORT = 3003;

app.use(cors());
app.use(express.json());

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = 'llama3-8b-8192';

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    cb(null, file.mimetype === 'application/pdf');
  }
});

app.get('/', (req, res) => {
  res.send('✅ ResumeGPT Backend (Groq Version) is Running');
});

app.post('/upload', upload.single('resume'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No PDF uploaded' });

    const buffer = fs.readFileSync(req.file.path);
    const pdfData = await pdfParse(buffer);
    fs.unlinkSync(req.file.path);

    const inputText = pdfData.text.slice(0, 4000);

   const prompt = `
You are a professional resume and career reviewer.

Given the resume below (between triple quotes), analyze it and return **all of the following fields**.
If any field is unclear or unknown, say "Not Available". Follow this exact format strictly:

---
ROLE: <The job or role this resume is best suited for>

SCORE: <Score out of 10 based on formatting, grammar, content, and style>

FEEDBACK: <General resume feedback paragraph>

ISSUES: <Formatting, grammar, or clarity issues>

SUGGESTIONS: <3–5 improvements to enhance the resume>

TECHNICAL SKILLS REQUIRED: <Technical skill set required for the role>

SOFT SKILLS REQUIRED: <Soft skills valued for this role>

PROJECTS THAT IMPRESS RECRUITERS: <Example projects that would stand out for this role>

JOB MARKET INSIGHT: <Insight on demand, salary trends, job placement rates for all levels globally>

LEARNING PATHS AND CERTIFICATIONS: <Recommended courses, certificates, or topics to improve fit>
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
        max_tokens: 2000
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error(`❌ Groq API Error [${response.status}]:`, errText);
      return res.status(500).json({ error: `Groq API returned ${response.status}: ${errText}` });
    }

    const result = await response.json();
    const rawText = result?.choices?.[0]?.message?.content || '';

    const extract = (label) => {
      const pattern = new RegExp(`${label}:\\s*([\\s\\S]*?)(?=\\n[A-Z ]+?:|$)`, 'i');
      const match = rawText.match(pattern);
      return match ? match[1].trim() : 'Not found';
    };

    const feedback = {
      role: extract('ROLE'),
      score: extract('SCORE'),
      feedback: extract('FEEDBACK'),
      issues: extract('ISSUES'),
      suggestions: extract('SUGGESTIONS'),
      technicalSkills: extract('TECHNICAL SKILLS REQUIRED'),
      softSkills: extract('SOFT SKILLS REQUIRED'),
      projects: extract('PROJECTS THAT IMPRESS RECRUITERS'),
      marketInsight: extract('JOB MARKET INSIGHT'),
      learningPaths: extract('LEARNING PATHS AND CERTIFICATIONS'),
      raw: rawText
    };

    res.json({
      message: '✅ Resume analyzed successfully',
      text: pdfData.text,
      feedback
    });

  } catch (err) {
    console.error('❌ Server Error:', err);
    res.status(500).json({ error: 'Failed to analyze resume' });
  }
});

app.listen(PORT, () => {
  console.log(`🟢 Server running at http://localhost:${PORT}`);
});
