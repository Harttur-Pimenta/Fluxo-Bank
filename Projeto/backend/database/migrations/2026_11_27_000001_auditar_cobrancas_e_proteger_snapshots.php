<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        if (DB::getDriverName() !== 'pgsql') {
            throw new RuntimeException('Auditoria exige PostgreSQL.');
        }

        // Novos registros preservam a estrutura integral (100% das chaves),
        // mas nunca gravam hashes de códigos, senhas ou tokens em claro.
        // Registros históricos permanecem imutáveis e exigem acesso restrito.
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.fn_auditoria_proteger_integral(dados jsonb)
            RETURNS jsonb LANGUAGE sql IMMUTABLE AS $fn$
                SELECT CASE WHEN dados IS NULL THEN NULL ELSE
                    (SELECT COALESCE(jsonb_object_agg(k,
                        CASE
                            WHEN lower(k) ~ '(password|senha|token|secret|segredo|codigo|cvv|authorization|api_key|chave_privada|pin|otp|hash|salt|payload|remember|session)'
                                THEN to_jsonb('[PROTEGIDO]'::text)
                            WHEN lower(k) IN ('cpf','cnpj','email','numero_cartao','cartao','documento','valor_chave','telefone','celular','phone')
                                THEN to_jsonb('[MASCARADO]'::text)
                            ELSE v END), '{}'::jsonb)
                       FROM jsonb_each(dados) AS x(k,v))
                END;
            $fn$;

            CREATE OR REPLACE FUNCTION public.fn_auditoria_por_tabela()
            RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $fn$
            DECLARE
                v_ant jsonb;
                v_dep jsonb;
                v_antes jsonb;
                v_depois jsonb;
                v_id text;
                v_destino text;
            BEGIN
                v_destino := format('%I.%I', TG_TABLE_SCHEMA, 'audit_' || TG_TABLE_NAME);
                IF TG_OP <> 'INSERT' THEN
                    v_ant := public.fn_auditoria_proteger_integral(to_jsonb(OLD));
                    v_antes := public.fn_auditoria_sanitizar(v_ant);
                END IF;
                IF TG_OP <> 'DELETE' THEN
                    v_dep := public.fn_auditoria_proteger_integral(to_jsonb(NEW));
                    v_depois := public.fn_auditoria_sanitizar(v_dep);
                END IF;
                v_id := COALESCE(v_dep->>'id', v_ant->>'id');

                EXECUTE format('INSERT INTO %s
                    (registro_id, operacao, usuario_id, request_id, antes, depois, diff,
                     antes_integral, depois_integral, registrado_em)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp())', v_destino)
                USING v_id, TG_OP,
                    CASE WHEN nullif(current_setting('fluxo.usuario_id', true), '') ~ '^[0-9]+$'
                         THEN nullif(current_setting('fluxo.usuario_id', true), '')::bigint ELSE NULL END,
                    CASE WHEN nullif(current_setting('fluxo.request_id', true), '') ~
                         '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                         THEN nullif(current_setting('fluxo.request_id', true), '')::uuid ELSE NULL END,
                    v_antes, v_depois,
                    CASE WHEN TG_OP = 'UPDATE' THEN public.fn_jsonb_diff(v_antes, v_depois) ELSE NULL END,
                    v_ant, v_dep;
                RETURN NULL;
            END;
            $fn$;
        SQL);

        // cobrancas_pix foi criada depois da migration original da auditoria física.
        DB::unprepared(<<<'SQL'
            CREATE TABLE IF NOT EXISTS public.audit_cobrancas_pix (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                registro_id TEXT NULL,
                operacao VARCHAR(6) NOT NULL CHECK (operacao IN ('INSERT','UPDATE','DELETE')),
                usuario_id BIGINT NULL, request_id UUID NULL,
                antes JSONB NULL, depois JSONB NULL, diff JSONB NULL,
                antes_integral JSONB NULL, depois_integral JSONB NULL,
                registrado_em TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            );
            CREATE INDEX IF NOT EXISTS audit_cobrancas_pix_registro_idx
                ON public.audit_cobrancas_pix (registro_id, registrado_em);
            CREATE INDEX IF NOT EXISTS audit_cobrancas_pix_data_idx
                ON public.audit_cobrancas_pix (registrado_em);
            DROP TRIGGER IF EXISTS trg_aud_cobrancas_pix ON public.cobrancas_pix;
            DROP TRIGGER IF EXISTS tg_auditoria_fisica_cobrancas_pix ON public.cobrancas_pix;
            CREATE TRIGGER tg_auditoria_fisica_cobrancas_pix
                AFTER INSERT OR UPDATE OR DELETE ON public.cobrancas_pix
                FOR EACH ROW EXECUTE FUNCTION public.fn_auditoria_por_tabela();
            DROP TRIGGER IF EXISTS tg_bloquear_auditoria ON public.audit_cobrancas_pix;
            CREATE TRIGGER tg_bloquear_auditoria
                BEFORE UPDATE OR DELETE ON public.audit_cobrancas_pix
                FOR EACH ROW EXECUTE FUNCTION public.fn_bloquear_mutacao_auditoria();
            DROP TRIGGER IF EXISTS tg_bloquear_truncate_auditoria ON public.audit_cobrancas_pix;
            CREATE TRIGGER tg_bloquear_truncate_auditoria
                BEFORE TRUNCATE ON public.audit_cobrancas_pix
                FOR EACH STATEMENT EXECUTE FUNCTION public.fn_bloquear_mutacao_auditoria();
            REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_cobrancas_pix FROM PUBLIC;
            REVOKE SELECT (antes_integral, depois_integral) ON public.audit_cobrancas_pix FROM PUBLIC;
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Auditoria append-only: não reverter e apagar histórico.');
    }
};
