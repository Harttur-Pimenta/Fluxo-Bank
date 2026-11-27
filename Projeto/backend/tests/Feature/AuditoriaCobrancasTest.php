<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use App\Models\CobrancaPix;
use Tests\TestCase;

class AuditoriaCobrancasTest extends TestCase
{
    use RefreshDatabase;

    public function test_cobranca_pix_tem_auditoria_fisica_e_campos_sensiveis_protegidos(): void
    {
        $usuario = $this->comChavePix($this->usuarioComConta());
        $dados = $this->withHeaders($this->autenticarSem2fa($usuario))
            ->postJson("{$this->api}/pix/cobrancas", [
                'valor_centavos' => 2500, 'descricao' => 'Teste de auditoria',
            ])->assertCreated()->json();
        $registro = DB::table('audit_cobrancas_pix')
            ->where('registro_id', (string) $dados['cobranca_id'])
            ->orderByDesc('id')->first();

        $this->assertNotNull($registro);
        $this->assertSame('INSERT', $registro->operacao);
        $integral = json_decode($registro->depois_integral, true);
        $this->assertArrayHasKey('hash_payload', $integral);
        $this->assertArrayHasKey('payload_emv', $integral);
        $this->assertSame('[PROTEGIDO]', $integral['hash_payload']);
        $this->assertSame('[PROTEGIDO]', $integral['payload_emv']);

        $this->assertSame('ATIVA', CobrancaPix::findOrFail($dados['cobranca_id'])->situacao());
    }

    public function test_requisicao_invalida_e_registrada_sem_expor_segredo(): void
    {
        $senha = 'meu-segredo-de-teste';
        $this->postJson("{$this->api}/login", [
            'email' => 'naoexiste@example.com', 'password' => $senha,
        ])->assertUnauthorized();

        $log = DB::table('logs_auditoria')->where('rota', 'api/v1/login')
            ->where('operacao', 'HTTP_POST')->latest('id')->first();

        $this->assertNotNull($log);
        $this->assertSame(401, $log->status_http);
        $this->assertStringNotContainsString($senha, $log->payload);
    }
}
