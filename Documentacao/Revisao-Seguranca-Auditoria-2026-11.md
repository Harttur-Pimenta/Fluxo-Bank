# Revisão técnica — segurança, operações e auditoria (27/11/2026)

## Diagnóstico (base: branch feature/melhorias-pix-kyc-2fa)

### Mudanças implementadas nesta revisão
1. **2FA** — desativação exige senha atual; ativação exige senha **e confirmação por código enviado ao e-mail**. Login continua desafiando conta com 2FA ativo. Reenvio é limitado por throttle. Código é armazenado com bcrypt (não SHA-256 simples), uso único e contador de erros com lock transacional; SHA-256 legado aceito apenas até expiração da janela existente. Cadastros novos não ativam 2FA sem confirmação.
2. **Pix** — cobranças só são geradas e pagas com conta recebedora ativa/aprovada; geração com expiração configurável, 5 min padrão, cancelamento e histórico. Pagamentos revalidam o estado sob lock.
3. **Auditoria HTTP** — identificador gerado no servidor, registro de sucesso e tentativa de registro de exceções (404, 401, 422, 500) com status mapeado, sem guardar senha/código/Pix completo.
4. **Auditoria por tabela** — migração nova instala `audit_cobrancas_pix` e trigger de INSERT/UPDATE/DELETE, trocando o trigger central legado. Para **novos eventos**, snapshots físicos preservam todas as **chaves de coluna**, mas protegem tokens, códigos, hashes, e-mails e documentos. O histórico anterior não foi alterado.
5. **Correlações** — inserido contexto de auditoria nos endpoints públicos relevantes de login, cadastro e 2FA.
6. **Testes** — novos cenários para 2FA, segurança e cobrança, correção de expectativa antiga que procurava a auditoria por trigger na tabela central. CI em GitHub Actions com PHP 8.4, PostgreSQL 16 e frontend Node 22.

## Riscos ainda existentes / que dependem de infraestrutura
- **Histórico sensível legado**: registros em `audit_*` anteriores à migração podem conter hashes de senhas, sessões e dados pessoais nos JSONB integrais. Pela política append-only, não reescrever automaticamente: controlar acesso no PostgreSQL, backup, definição de retenção e avaliação LGPD.
- **Imutabilidade limitada**: triggers e REVOKE PUBLIC não impedem que o proprietário do banco ou um administrador privilegiado os desative. Para garantia forte, usar papel de aplicação com privilégio mínimo, banco/armazenamento WORM ou trilha externa com assinatura. O atual hash encadeado não cobre todos os logs emitidos pelo serviço.
- **E-mail e notificações**: entrega por Resend HTTPS depende de chave, domínio remetente verificado, rede e disponibilidade do provedor; aceite HTTP não garante caixa de entrada. Falhas KYC são logadas, mas **não há outbox transacional com reenvio automático**.
- **Agendamentos**: dependem do executor agendado, que não acompanha automaticamente o Web Service gratuito do Render. Verificar worker/cron e comportamento pós-reinício.
- **2FA avançado**: reautenticação por operação de alto risco e recuperação independente de conta ficam pendentes de desenho próprio e testes de segurança.
- **Cabeçalhos de proxy/limite de requisições**: revisar TRUSTED_PROXIES, TLS e IP real no Render; não presumir que o IP visto no log é confiável sem essa validação.
- **Segredos expostos por capturas anteriores**: rotacionar credenciais do banco; APP_KEY requer plano específico de migração/recriptografia de sessões e códigos Pix cifrados, nunca rotação improvisada.
- **Modelo de cobrança**: só Pix interno simulado; não há transferência bancária real nem liquidação por rede Pix externa.
- **Otimização da auditoria**: saúde e polling frequente podem gerar muito volume no banco gratuito. Avaliar volume, política de armazenamento e retenção antes de escalar.

## Verificações antes do merge
- Executar GitHub Actions e corrigir falhas reais do workflow; dependências e PostgreSQL não estavam disponíveis no ambiente da revisão manual.
- Validar migration incremental em PostgreSQL 16 com dados existentes e backup; confirmar triggers, esquema e privacidade.
- Validar concorrência (2 pessoas pagando a mesma cobrança; cancelamento concorrente; reenvio de 2FA).
- Testar e-mail de ativação 2FA, notificação de aprovação e recusa KYC, e falhas de provedor.
- Testar cliente tentando acessar administração e visualizar contas/cartões/solicitações de terceiros.
- Testar saldos/lancamentos, idempotência em requisições repetidas e recuperação de sessão após reboot.
- Revisar contratos OpenAPI, documentação acadêmica, mensagens de UX e índices antes de mesclar.
