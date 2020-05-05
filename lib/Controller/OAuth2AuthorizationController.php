<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Controller;

use League\OAuth2\Server\AuthorizationServer;
use SimpleSAML\Modules\OpenIDConnect\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use SIU\AraiUsuarios\IDP\Factory;
use SimpleSAML\Auth;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use SimpleSAML\Session;

class OAuth2AuthorizationController
{
    use GetClientFromRequestTrait;

    /**
     * @var AuthenticationService
     */
    private $authenticationService;

    /**
     * @var AuthorizationServer
     */
    private $authorizationServer;


    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository $clientRespository
     * @param \SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService $authenticationService
     * @param \League\OAuth2\Server\AuthorizationServer $authorizationServer
     */
    public function __construct(
        ClientRepository $clientRepository,
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer
    ) {
        $this->clientRepository = $clientRepository;
        $this->authenticationService = $authenticationService;
        $this->authorizationServer = $authorizationServer;
    }


    /**
     * @param \Zend\Diactoros\ServerRequest $request
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(ServerRequest $request): \Psr\Http\Message\ResponseInterface
    {
        $client = $this->getClientFromRequest($request, true);
        $authSource = $client->getAuthSource();
        $user = $this->authenticationService->getAuthenticateUser($authSource, [ 
            'RPMetadata' => [
                'client_id' => $client->getIdentifier(),
                'app_unique_id' => $client->getUsuariosAppUniqueId(),
                '__nombre' => $client->getName(),
            ]
        ]);

        $usuariosManager = Factory::getUsuariosManager();
        list($permiteAcceso, $msg) = $usuariosManager->verificarAcceso($user->getIdentifier(), $client->getUsuariosAppUniqueId());

        if (! $permiteAcceso ) {
            $contexto = [
                'usuario' => $usuario,
                'aplicacion' => $appId,
                'mensaje' => $msg
            ];

            Factory::getIdpLogger()->warning('OIDC Acceso denegado', $contexto);
            $this->redirect403($client->getUsuariosUrl());
        } 

        $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($request);
        $authorizationRequest->setUser($user);
        $authorizationRequest->setAuthorizationApproved(true);

        return $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, new Response());
    }

    protected function redirect403($returnTo) 
    {
        $state = Session::getSessionFromRequest()->getAuthState('usuarios_arai');
        $state['OIDCReturnTo'] = (empty($returnTo)) ? Utils\HTTP::getSelfURL() : $returnTo;
        // Save state and redirect to 403 page
        $id = Auth\State::saveState($state, 'arai:runChecks');
        $url = Module::getModuleURL('arai/authorize_403.php');
        Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }
}
