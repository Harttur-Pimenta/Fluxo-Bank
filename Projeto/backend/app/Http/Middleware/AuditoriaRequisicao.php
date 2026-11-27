<?php

namespace App\Http\Middleware;

use App\Services\AuditoriaService;
use App\Support\Sanitizador;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/** Registra sucessos e exceções sem colocar segredos nos logs. */
class AuditoriaRequisicao
{
    public function __construct(private AuditoriaService $auditoria) {}

    public function handle(Request $request, Closure $next): Response
    {
        // Um identificador de auditoria nunca é controlado por quem fez a requisição.
        $requestId = (string) Str::uuid();
        $request->attributes->set('request_id', $requestId);

        try {
            $response = $next($request);
        } catch (\Throwable $erro) {
            $status = $erro instanceof HttpExceptionInterface ? $erro->getStatusCode() : 500;
            if ($erro instanceof \Illuminate\Validation\ValidationException) {
                $status = $erro->status;
            } elseif ($erro instanceof \Illuminate\Auth\AuthenticationException) {
                $status = 401;
            }
            $this->registrar($request, $status);
            throw $erro;
        }

        $response->headers->set('X-Request-Id', $requestId);
        $this->registrar($request, $response->getStatusCode());
        return $response;
    }

    private function registrar(Request $request, int $status): void
    {
        try {
            $this->auditoria->registrar(
                $this->auditoria->categoriaDaRequisicao($request),
                'HTTP_'.$request->method(),
                [
                    'rota' => $request->path(),
                    'metodo' => $request->method(),
                    'status_http' => $status,
                    'dados' => Sanitizador::dadosDaRequisicao($request->input()),
                ],
                'http', null, $request->user()?->id, $request, $status,
            );
        } catch (\Throwable $falhaLog) {
            report($falhaLog);
        }
    }
}
