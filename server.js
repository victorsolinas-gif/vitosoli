import express from 'express'
import Anthropic from '@anthropic-ai/sdk'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import cors from 'cors'

const __dirname = dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.PORT || 3000

// ── Middleware ──
app.use(cors({
  origin: ['https://vitosoli.com', 'http://localhost:3000'],
  methods: ['POST', 'GET']
}))
app.use(express.json())
app.use(express.static(__dirname)) // sert chat-ia.html

// ── Client Anthropic ──
const client = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
})

// ── Route principale : chat ──
app.post('/chat', async (req, res) => {
  const { messages, system } = req.body

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages requis' })
  }

  try {
    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1000,
      system: system || "Tu es Vitosoli, un assistant IA intelligent et bienveillant. Tu réponds en français par défaut, de façon claire, précise et engageante.",
      messages
    })

    res.json({ reply: response.content[0].text })

  } catch (error) {
    console.error('Erreur API Anthropic:', error.message)
    res.status(500).json({ error: 'Erreur lors de la communication avec Claude.' })
  }
})

// ── Healthcheck ──
app.get('/health', (_, res) => res.json({ status: 'ok' }))

app.listen(PORT, () => {
  console.log(`✦ Vitosoli server running → http://localhost:${PORT}`)
})
