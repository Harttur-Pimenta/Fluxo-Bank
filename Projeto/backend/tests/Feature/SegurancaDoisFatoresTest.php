<?php

namespace Tests\Feature;

use App\Models\CodigoVerificacao;
use App\Services\Servico2FA;
use App\Exceptions\RegraDeNegocioException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class SegurancaDoisFatoresTest extends TestCase
{
    use RefreshDatabase;

    private function configurarEmail(): void
    {
        config()->set('fluxo.email.provedor', 'resend');
        config()->set('services.resend.key', 'test-key');
        config()->set('mail.from.address', 'notificacoes@example.com');
        config()->set('mail.from.name', 'Fluxo Bank');
        config()->set('fluxo.dois_fatores.canal', 'EMAIL');
        config()->set('fluxo.dois_fatores.entrega_email_ativa', true);
        Http::fake(['api.resend.com/*' => Http::response(['id' => 'teste-001'], 200)]);
    }

    public function test_ativacao_exige_senha_e_confirmacao_por_email(): void
    {
        $this->configurarEmail();
        $user = $this->usuarioComConta();
        $h = $this->autenticarSem2fa($user);

        $this->withHeaders($h)->postJson("{$this->api}/2fa/ativar", [])->assertStatus(422);
        $this->withHeaders($h)->postJson("{$this->api}/2fa/ativar", [
            'senha_atual' => 'errada',
        ])->assertStatus(422);
        $this->assertFalse((bool) $user->refresh()->dois_fatores_ativo);

        $inicio = $this->withHeaders($h)->postJson("{$this->api}/2fa/ativar", [
            'senha_atual' => 'senha123',
        ])->assertStatus(202);
        $this->assertFalse((bool) $user->refresh()->dois_fatores_ativo);
        $codigo = $inicio->json('codigo_teste');
        $this->assertSame(6, strlen($codigo));

        $this->withHeaders($h)->postJson("{$this->api}/2fa/confirmar-ativacao", [
            'codigo' => $codigo,
        ])->assertOk();
        $this->assertTrue((bool) $user->refresh()->dois_fatores_ativo);

        $this->assertSame(0, $user->tokens()->count(), 'Todos os tokens antigos devem ser revogados.');
        $this->app['auth']->forgetGuards(); // Remove o cache de guarda da requisição anterior nos testes.
        $this->withHeaders($h)->getJson("{$this->api}/eu")->assertUnauthorized();
    }

    public function test_desativacao_exige_senha_atual(): void
    {
        $user = $this->usuarioComConta();
        $user->forceFill(['dois_fatores_ativo' => true])->save();
        $headers = $this->autenticarSem2fa($user);
        $this->withHeaders($headers)->postJson("{$this->api}/2fa/desativar", [])->assertStatus(422);
        $this->withHeaders($headers)->postJson("{$this->api}/2fa/desativar", [
            'senha_atual' => 'invalida',
        ])->assertStatus(422);
        $this->withHeaders($headers)->postJson("{$this->api}/2fa/desativar", [
            'senha_atual' => 'senha123',
        ])->assertOk();
        $this->assertFalse((bool) $user->refresh()->dois_fatores_ativo);
    }

    public function test_codigo_nao_pode_ser_reutilizado_e_nao_e_sha256_reversivel(): void
    {
        $this->configurarEmail();
        $user = $this->usuarioComConta();
        $servico = app(Servico2FA::class);
        $codigo = $servico->gerar($user, CodigoVerificacao::FINALIDADE_ATIVACAO_2FA)['codigo'];
        $registro = CodigoVerificacao::where('user_id', $user->id)->latest('id')->firstOrFail();

        $this->assertStringStartsWith('$2y$', $registro->codigo_hash);
        $this->assertSame(60, strlen($registro->codigo_hash));
        $servico->validar($user, $codigo, CodigoVerificacao::FINALIDADE_ATIVACAO_2FA);

        try {
            $servico->validar($user, $codigo, CodigoVerificacao::FINALIDADE_ATIVACAO_2FA);
            $this->fail('Código já utilizado deveria ser recusado.');
        } catch (RegraDeNegocioException $e) {
            $this->assertSame(401, $e->statusHttp());
        }
    }

    public function test_tentativas_incorretas_persistem_sem_rollback(): void
    {
        $this->configurarEmail();
        $user = $this->usuarioComConta();
        $servico = app(Servico2FA::class);
        $codigo = $servico->gerar($user, CodigoVerificacao::FINALIDADE_ATIVACAO_2FA)['codigo'];
        $errado = $codigo === '000000' ? '999999' : '000000';

        for ($tentativa = 1; $tentativa <= 3; $tentativa++) {
            try {
                $servico->validar($user, $errado, CodigoVerificacao::FINALIDADE_ATIVACAO_2FA);
                $this->fail('Código incorreto não pode validar.');
            } catch (RegraDeNegocioException $e) {
                $this->assertContains($e->statusHttp(), [401, 429]);
            }
        }
        $registro = CodigoVerificacao::where('user_id', $user->id)->latest('id')->firstOrFail();
        $this->assertSame(3, $registro->tentativas);
        $this->expectException(RegraDeNegocioException::class);
        $servico->validar($user, $codigo, CodigoVerificacao::FINALIDADE_ATIVACAO_2FA);
    }
}
