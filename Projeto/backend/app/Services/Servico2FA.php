<?php

namespace App\Services;

use App\Exceptions\RegraDeNegocioException;
use App\Models\CodigoVerificacao;
use App\Models\User;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;

class Servico2FA
{
    /**
     * @return array{codigo:string, canal:string, expira_em:string}
     */
    public function gerar(User $user, string $finalidade): array
    {
        $canal = config('fluxo.dois_fatores.canal');
        $validade = (int) config('fluxo.dois_fatores.validade_minutos');
        if (app()->environment('production') && ($canal !== 'EMAIL'
            || ! config('fluxo.dois_fatores.entrega_email_ativa')
            || ! app(EntregaEmailService::class)->disponivel())) {
            throw new RegraDeNegocioException('Entrega de códigos por e-mail indisponível.', 503);
        }

        CodigoVerificacao::where('user_id', $user->id)
            ->where('finalidade', $finalidade)
            ->whereNull('utilizado_em')
            ->update(['utilizado_em' => now()]);

        $codigo = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        $registro = CodigoVerificacao::create([
            'user_id' => $user->id,
            'canal' => $canal,
            'finalidade' => $finalidade,
            'codigo_hash' => Hash::driver('bcrypt')->make($codigo), // 60 caracteres, resistência a brute force offline
            'expira_em' => now()->addMinutes($validade),
            'max_tentativas' => (int) config('fluxo.dois_fatores.max_tentativas'),
        ]);

        if ($canal === 'EMAIL' && config('fluxo.dois_fatores.entrega_email_ativa', false)) {
            try {
                app(EntregaEmailService::class)->enviar($user->email, 'Fluxo Bank — código de segurança',
                    'Seu código de acesso ao Fluxo é '.$codigo.'. Ele expira em '.$validade.' minutos. Nunca compartilhe este código.');
            } catch (\Throwable $e) {
                Log::error('Falha no envio de 2FA', ['user_id' => $user->id, 'erro' => $e->getMessage()]);
                throw new RegraDeNegocioException('Não foi possível enviar o código de segurança.', 503);
            }
        }

        Log::info('Codigo 2FA gerado', [
            'user_id' => $user->id,
            'canal' => $canal,
            'finalidade' => $finalidade,
            'expira_em' => $registro->expira_em->toIso8601String(),
        ]);

        return [
            'codigo' => $codigo,
            'canal' => $canal,
            'expira_em' => $registro->expira_em->toIso8601String(),
        ];
    }

    public function validar(User $user, string $codigo, string $finalidade): CodigoVerificacao
    {
        // A transação confirma o contador de tentativas antes de retornar o erro.
        // Lançar a exceção dentro da transação faria rollback do incremento.
        $resultado = DB::transaction(function () use ($user, $codigo, $finalidade) {
            $registro = CodigoVerificacao::where('user_id', $user->id)
                ->where('finalidade', $finalidade)
                ->whereNull('utilizado_em')
                ->latest('id')->lockForUpdate()->first();

            if (! $registro) return ['erro' => 'Nenhum código pendente. Solicite um novo.', 'status' => 401];
            if ($registro->expira_em->isPast()) return ['erro' => 'Código expirado. Solicite um novo.', 'status' => 401];
            if ($registro->tentativas >= $registro->max_tentativas) {
                return ['erro' => 'Número de tentativas excedido. Solicite um novo código.', 'status' => 429];
            }
            $correto = strlen($registro->codigo_hash) === 64
                ? hash_equals($registro->codigo_hash, hash('sha256', $codigo)) // desafios legados (expiram rapidamente)
                : Hash::driver('bcrypt')->check($codigo, $registro->codigo_hash);
            if (! $correto) {
                $registro->increment('tentativas');
                $registro->refresh();
                return [
                    'erro' => 'Código inválido. Tentativas restantes: '.
                        max(0, $registro->max_tentativas - $registro->tentativas).'.',
                    'status' => 401,
                ];
            }
            $registro->update(['utilizado_em' => now()]);
            return ['registro' => $registro];
        });

        if (isset($resultado['erro'])) {
            throw new RegraDeNegocioException($resultado['erro'], $resultado['status']);
        }
        return $resultado['registro'];
    }
}
