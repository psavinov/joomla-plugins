<?php
/**
 * @author      Pavel Savinov
 * @package     Joomla.Plugin
 * @subpackage  Authentication.fiware
 *
 * @copyright   Copyright (C) 2005 - 2017 Pavel Savinov, Inc. All rights reserved.
 * @license     MIT License; see LICENSE.txt
 */

defined('_JEXEC') or die;

use Joomla\Registry\Registry;

/**
 * FiWare IDM Authentication Plugin
 *
 * @since  1.5
 */
class PlgAuthenticationFiware extends JPlugin
{
    /**
     * This method should handle any authentication and report back to the subject
     *
     * @param   array $credentials Array holding the user credentials
     * @param   array $options Array of extra options
     * @param   object &$response Authentication response object
     *
     * @return  boolean
     *
     * @since   1.5
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        $success = false;

        $curlParams = array(
            'follow_location' => true,
            'transport.curl' => array(
                CURLOPT_SSL_VERIFYPEER => 1
            ),
        );

        $transportParams = new Registry($curlParams);

        try {
            $http = JHttpFactory::getHttp($transportParams, 'curl');
        } catch (RuntimeException $e) {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->type = 'Fiware';
            $response->error_message = JText::sprintf('JGLOBAL_AUTH_FAILED', JText::_('JGLOBAL_AUTH_CURL_NOT_INSTALLED'));

            return;
        }

        // Check if we have a username and password

        if ($credentials['username'] === '' || $credentials['password'] === '') {
            $response->type = 'Fiware';
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::sprintf('JGLOBAL_AUTH_FAILED', JText::_('JGLOBAL_AUTH_USER_BLACKLISTED'));

            return;
        }

        $blacklist = explode(',', $this->params->get('user_blacklist', ''));

        // Check if the username isn't blacklisted

        if (in_array($credentials['username'], $blacklist)) {
            $response->type = 'Fiware';
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::sprintf('JGLOBAL_AUTH_FAILED', JText::_('JGLOBAL_AUTH_USER_BLACKLISTED'));

            return;
        }

        $data = array(
            "auth" => array(
                "identity" => array(
                    "methods" => array("password"),
                    "password" => array(
                        "user" => array(
                            "name" => $credentials['username'],
                            "domain" => array("id" => "default"),
                            "password" => $credentials['password']
                        )
                    )
                )
            )
        );

        $headers = array(
            "Content-Type" => "application/json"
        );

        try {
            $endpoint = $this->params->get('endpoint', 'http://192.168.99.100:5000/v3/');

            $result = $http->post($endpoint . 'auth/tokens', json_encode($data), $headers);
        } catch (Exception $e) {
            // If there was an error in the request then create a 'false' dummy response.

            $result = new JHttpResponse;
            $result->code = false;
        }

        $code = $result->code;

        switch ($code) {
            case 201 :
                $message = JText::_('JGLOBAL_AUTH_ACCESS_GRANTED');
                $success = true;
                break;

            case 401 :
                $message = JText::_('JGLOBAL_AUTH_ACCESS_DENIED');
                break;

            default :
                $message = JText::_('JGLOBAL_AUTH_UNKNOWN_ACCESS_DENIED');
                break;
        }

        $response->type = 'Fiware';

        if (!$success) {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::sprintf('JGLOBAL_AUTH_FAILED', $message);

            return;
        }

        $email = $credentials['username'];

        // Extra security checks with existing local accounts

        $db = JFactory::getDbo();

        $query = $db->getQuery(true)
            ->select('id, activation, username, email, block')
            ->from('#__users')
            ->where('email = ' . $db->quote($email));

        $db->setQuery($query);

        if ($localUser = $db->loadObject()) {
            if ($email !== $localUser->email) {
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('PLG_FIWARE_ERROR_CONFLICT');

                return;
            } else if ($localUser->block || !empty($localUser->activation)) {
                // Existing user disabled locally

                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('JGLOBAL_AUTH_ACCESS_DENIED');

                return;
            }

            // We will always keep the local username for existing accounts

            $credentials['username'] = $localUser->username;
            $email = $localUser->email;

        } else if (JFactory::getApplication()->isClient('administrator')) {
            // We wont' allow backend access without local account

            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JERROR_LOGIN_DENIED');

            return;
        }

        $response->status = JAuthentication::STATUS_SUCCESS;
        $response->error_message = '';
        $response->email = $email;

        // Reset the username to what we ended up using

        $response->username = $credentials['username'];
        $response->fullname = $credentials['username'];
    }
}