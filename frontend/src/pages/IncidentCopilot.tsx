import React, { useEffect, useRef, useState } from 'react'
import { Box, Button, Card, CardContent, Chip, Divider, Stack, TextField, Typography } from '@mui/material'
import { Link as RouterLink, useSearchParams } from 'react-router-dom'
import { ErrorState, PageHeader } from '../components/ui'
import {
  chatWithIncidentCopilot,
  generateIncidentSummary,
  getIncidentConversation,
  listIncidentConversations,
  AIChatResponse,
  AIIncidentSummary,
} from '../services/api'
import { formatDateTimePKT } from '../utils/time'

const promptSuggestions = [
  'Summarize this incident',
  'What should I do next?',
  'Why is this suspicious?',
  'Show suspicious commands',
  'Recommend containment',
  'What MITRE techniques are involved?',
  'What evidence supports this?',
  'Generate an executive report',
]

const providerLabel = (provider: string): string => {
  if (provider === 'openai') return 'OpenAI'
  if (provider === 'local_deterministic') return 'Deterministic fallback'
  if (provider.toLowerCase().includes('gemini')) return 'Gemini (historical)'
  return provider
}

const IncidentCopilot: React.FC = () => {
  const [searchParams] = useSearchParams()
  const [incidentId, setIncidentId] = useState(() => searchParams.get('incidentId') || '')
  const [message, setMessage] = useState('Summarize this incident')
  const [conversationId, setConversationId] = useState<string | null>(null)
  const [chat, setChat] = useState<AIChatResponse | null>(null)
  const [history, setHistory] = useState<AIChatResponse['messages']>([])
  const [summary, setSummary] = useState<AIIncidentSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const pendingChatRequest = useRef<string | null>(null)

  useEffect(() => {
    if (!/^[0-9a-f-]{36}$/i.test(incidentId)) {
      setConversationId(null)
      setHistory([])
      return
    }
    let active = true
    listIncidentConversations(incidentId)
      .then(async (conversations) => {
        if (!active || conversations.length === 0) return
        const conversation = await getIncidentConversation(incidentId, conversations[0].id)
        if (!active) return
        setConversationId(conversation.id)
        setHistory(conversation.messages)
      })
      .catch(() => {
        if (active) {
          setConversationId(null)
          setHistory([])
        }
      })
    return () => {
      active = false
    }
  }, [incidentId])

  const run = async (action: () => Promise<void>) => {
    try {
      setLoading(true)
      setError(null)
      await action()
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'AI request failed')
    } finally {
      setLoading(false)
    }
  }

  const askCopilot = async () => {
    if (pendingChatRequest.current) return
    const requestId = crypto.randomUUID()
    pendingChatRequest.current = requestId
    try {
      await run(async () => {
        const result = await chatWithIncidentCopilot(incidentId, message, conversationId, requestId)
        setChat(result)
        setConversationId(result.conversation_id)
        setHistory(result.messages)
      })
    } finally {
      pendingChatRequest.current = null
    }
  }

  return (
    <Box sx={{ maxWidth: 1100, mx: 'auto' }}>
      <PageHeader title="Triage AI" description="OpenAI-powered answers grounded only in tenant-scoped incident evidence" />
      {error && <ErrorState message={error} onRetry={() => setError(null)} />}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Stack spacing={2}>
            <TextField label="Incident ID" value={incidentId} onChange={(e) => setIncidentId(e.target.value)} fullWidth />
            <TextField label="Question" value={message} onChange={(e) => setMessage(e.target.value)} fullWidth multiline minRows={3} />
            <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
              {promptSuggestions.map((prompt) => (
                <Chip
                  key={prompt}
                  label={prompt}
                  variant={message === prompt ? 'filled' : 'outlined'}
                  color={message === prompt ? 'primary' : 'default'}
                  onClick={() => setMessage(prompt)}
                />
              ))}
            </Stack>
            <Stack direction="row" spacing={1}>
              <Button disabled={!incidentId || loading} variant="contained" onClick={askCopilot}>{loading ? 'Working...' : 'Ask Triage AI'}</Button>
              <Button disabled={!incidentId || loading} variant="outlined" onClick={() => run(async () => setSummary(await generateIncidentSummary(incidentId)))}>
                Generate Summary
              </Button>
            </Stack>
          </Stack>
        </CardContent>
      </Card>
      {chat && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6">Answer</Typography>
            <Typography sx={{ whiteSpace: 'pre-wrap', mt: 1 }}>{chat.answer}</Typography>
            <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 2 }}>
              <Chip size="small" label={`${chat.confidence}% confidence`} color="info" variant="outlined" />
              <Chip size="small" label={`${providerLabel(chat.provider)} / ${chat.model}`} variant="outlined" />
              {chat.fallback_used && <Chip size="small" label="Deterministic fallback" color="warning" variant="outlined" />}
              {chat.token_usage?.total_tokens != null && (
                <Chip
                  size="small"
                  label={`${chat.token_usage.total_tokens} tokens (${chat.token_usage.input_tokens ?? 0} in / ${chat.token_usage.output_tokens ?? 0} out)`}
                  variant="outlined"
                />
              )}
            </Stack>
            <Divider sx={{ my: 3 }} />
            <Typography variant="subtitle1">Evidence references</Typography>
            {chat.evidence_references.length > 0 ? (
              <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}>
                {chat.evidence_references.map((reference) => {
                  return reference.available !== false && reference.navigation_path ? (
                    <Button
                      key={`${reference.type}-${reference.id}`}
                      component={RouterLink}
                      to={reference.navigation_path}
                      size="small"
                      variant="outlined"
                    >
                      {reference.type}: {reference.label}
                    </Button>
                  ) : (
                    <Chip
                      key={`${reference.type}-${reference.id}`}
                      label={`${reference.type}: ${reference.label}`}
                      size="small"
                      title={reference.unavailable_reason || 'No safe navigation target is available.'}
                    />
                  )
                })}
              </Stack>
            ) : (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>No supporting reference is available for this answer.</Typography>
            )}
            {chat.limitations.length > 0 && (
              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" color="warning.main">Evidence limitations</Typography>
                {chat.limitations.map((item) => <Typography key={item} variant="body2" color="text.secondary">{item}</Typography>)}
              </Box>
            )}
            {chat.suggested_follow_up_questions.length > 0 && (
              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>Suggested follow-up questions</Typography>
                <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                  {chat.suggested_follow_up_questions.map((question) => (
                    <Chip key={question} label={question} onClick={() => setMessage(question)} variant="outlined" />
                  ))}
                </Stack>
              </Box>
            )}
          </CardContent>
        </Card>
      )}
      {history.length > 0 && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="subtitle1" sx={{ mb: 2 }}>Conversation History</Typography>
            <Stack spacing={2}>
              {history.map((item) => (
                <Box
                  key={item.id}
                  sx={{
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 2,
                    p: 2,
                    bgcolor: item.role === 'user' ? 'rgba(56, 189, 248, 0.08)' : 'background.paper',
                  }}
                >
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <Chip size="small" label={item.role === 'user' ? 'Analyst' : 'Triage AI'} />
                    <Typography variant="caption" color="text.secondary">
                      {formatDateTimePKT(item.created_at)}
                    </Typography>
                  </Stack>
                  <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>{item.content}</Typography>
                </Box>
              ))}
            </Stack>
          </CardContent>
        </Card>
      )}
      {summary && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6">AI Incident Summary</Typography>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Executive Summary</Typography>
            <Typography>{summary.executive_summary}</Typography>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Technical Summary</Typography>
            <Typography>{summary.technical_summary}</Typography>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Root Cause</Typography>
            <Typography>{summary.root_cause}</Typography>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Impact</Typography>
            <Typography>{summary.impact}</Typography>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Next Steps</Typography>
            {summary.recommended_next_steps.map((item) => <Typography key={item}>- {item}</Typography>)}
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Suggested Containment</Typography>
            {summary.suggested_containment.map((item) => <Typography key={item}>- {item}</Typography>)}
            <Typography variant="subtitle2" sx={{ mt: 2 }}>MITRE ATT&CK</Typography>
            {summary.suggested_mitre_attack_techniques.length > 0 ? (
              <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}>
                {summary.suggested_mitre_attack_techniques.map((technique, index) => (
                  <Chip
                    key={`${technique.technique_id || technique.id || index}`}
                    label={`${technique.technique_id || technique.id || 'ATT&CK'} ${technique.technique_name || technique.name || ''}`.trim()}
                    color="warning"
                    variant="outlined"
                  />
                ))}
              </Stack>
            ) : (
              <Typography color="text.secondary">No ATT&CK mapping returned.</Typography>
            )}
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
              Confidence score: {summary.confidence_score}%
            </Typography>
          </CardContent>
        </Card>
      )}
    </Box>
  )
}

export default IncidentCopilot
