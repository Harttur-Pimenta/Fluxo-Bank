<?php

namespace Tests\Feature;

use App\Models\Conta;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class SolicitacaoAberturaTest extends TestCase
{
    use RefreshDatabase;

    public function test_cadastro_manual_cria_solicitacao_que_so_backoffice_pode_aprovar(): void
    {
        config()->set('fluxo.kyc.automatico', false);
        $cadastro = $this->postJson("{$this->api}/cadastro", [
            'nome' => 'Carla de Teste',
            'cpf' => '529.982.247-25',
            'data_nascimento' => '1998-01-10',
            'email' => 'carla.manual@fluxo.test',
            'password' => 'senha12345',
        ])->assertCreated()->assertJsonPath('status_abertura', 'EM_ANALISE');

        $usuario = User::where('email', 'carla.manual@fluxo.test')->firstOrFail();
        $conta = $usuario->conta()->firstOrFail();
        $this->assertSame(Conta::STATUS_PENDENTE, $conta->status);
        $this->assertFalse($conta->podeDebitar());

        $this->withHeaders($this->autenticarSem2fa($usuario))
            ->postJson("{$this->api}/backoffice/contas/{$conta->id}/kyc/aprovar")
            ->assertForbidden();

        $admin = User::factory()->backoffice()->create();
        $this->withHeaders($this->autenticarSem2fa($admin))
            ->postJson("{$this->api}/backoffice/contas/{$conta->id}/kyc/aprovar")
            ->assertOk();

        $this->assertSame(Conta::ABERTURA_APROVADA, $conta->refresh()->status_abertura);
        $this->assertTrue($conta->podeDebitar());
    }
}
