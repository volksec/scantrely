# Playwright Pentest Agent

Automação Python baseada em Playwright para recon seguro e tech-aware.

## Ideia central

O pipeline faz fingerprint primeiro e só então decide o que vale executar.
Se a aplicação parece React/Next/Nuxt/Vue/Angular, a lógica de ViewState é
explicitamente ignorada. Se aparecer ASP.NET WebForms, aí sim a análise de
`__VIEWSTATE` e `__EVENTVALIDATION` entra no plano.

## Uso

```bash
python -m playwright_agent.agent recon \
  --url https://example.com \
  --auth-state auth-a.json \
  --auth-state-b auth-b.json \
  --max-pages 50 \
  --max-depth 3 \
  --headless \
  --output reports/example-report.md
```

## Saídas

- `evidence/session.json`
- `evidence/pages/`
- `evidence/idor/`
- `reports/report.md`

## Observação

Instale o Playwright e o Chromium antes de rodar:

```bash
pip install playwright
playwright install chromium
```
