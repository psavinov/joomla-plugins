<?php
/**
 * @author      Pavel Savinov
 * @package     Joomla.Plugin
 * @subpackage  User.fiwareuser
 *
 * @copyright   Copyright (C) 2005 - 2017 Pavel Savinov. All rights reserved.
 * @license     MIT License; see LICENSE.txt
 */

defined('_JEXEC') or die;

use Joomla\Registry\Registry;

/**
 * Class for Fiware IDM entity creator.
 *
 * A tool to automatically create and synchronise Fiware IDM account for user.
 *
 * @since  1.6
 */
class PlgUserFiwareUser extends JPlugin
{

    /**
     * Utility method to act on a user after it has been saved.
     *
     * This method creates a Fiware IDM entity for user.
     *
     * @param   array $user Holds the new user data.
     * @param   boolean $isnew True if a new user is stored.
     * @param   boolean $success True if user was succesfully stored in the database.
     * @param   string $msg Message.
     *
     * @return  boolean
     *
     * @since   1.6
     */
    public function onUserAfterSave($user, $isnew, $success, $msg)
    {

        // If the user wasn't stored we don't resync

        if (!$success) {
            return false;
        }

        // Ensure the user id is really an int

        $user_id = (int)$user['id'];

        // If the user id appears invalid then bail out just in case

        if (empty($user_id) || empty($user['password_clear'])) {
            return false;
        }

        $data = array(
            "auth" => array(
                "identity" => array(
                    "methods" => array("password"),
                    "password" => array(
                        "user" => array(
                            "name" => $this->params->get('admin', 'idm'),
                            "domain" => array("id" => "default"),
                            "password" => $this->params->get('password', 'idm')
                        )
                    )
                )
            )
        );

        $headers = array(
            "Content-Type" => "application/json"
        );

        $curlParams = array(
            'follow_location' => true,
            'transport.curl' => array(
                CURLOPT_SSL_VERIFYPEER => 1
            ),
        );

        $transportParams = new Registry($curlParams);

        try {
            $http = JHttpFactory::getHttp($transportParams, 'curl');

            $endpoint = $this->params->get('endpoint', 'http://192.168.99.100:5000/v3/');

            $result = $http->post($endpoint . 'auth/tokens', json_encode($data), $headers);
        } catch (Exception $e) {
            return false;
        }

        $code = $result->code;

        $token = '';

        if ($code === 201) {
            $token = $result->headers['X-Subject-Token'];
        }

        if ($token !== '') {
            $headers = array(
                "Content-Type" => "application/json",
                "X-Auth-Token" => $token
            );

            try {
                if ($isnew) {
                    $userData = array(
                        "user" => array(
                            "name" => $user['email'],
                            "password" => $user['password_clear']
                        )
                    );

                    $userResult = $http->post($endpoint . 'users', json_encode($userData), $headers);
                    $userObject = json_decode($userResult->body);

                    if ($userObject->{'user'}->{'enabled'}) {
                        return true;
                    }
                } else {
                    $userData = array(
                        "user" => array(
                            "password" => $user['password_clear']
                        )
                    );

                    $userListResult = $http->get($endpoint . 'users?name=' . $user['email'], $headers);
                    $userList = json_decode($userListResult->body);

                    if (count($userList->{'users'}) != 1) {
                        return false;
                    }

                    $idmUserId = $userList->{'users'}[0]->{'id'};

                    $userResult = $http->patch($endpoint . 'users/' . $idmUserId, json_encode($userData), $headers);

                    $userObject = json_decode($userResult->body);

                    if ($userObject->{'user'}->{'enabled'}) {
                        return true;
                    }
                }

            } catch (Exception $e) {
                return false;
            }
        }

        return false;
    }

    /**
     * Utility method to act on a user before it has been saved.
     *
     * This method checks if user already exists in Fiware IDM.
     *
     * @param   array $olduser Holds the old user data.
     * @param   boolean $isnew True if a new user is stored.
     * @param   array $newuser Holds the new user data.
     *
     * @return  boolean
     *
     * @since   1.6
     */
    public function onUserBeforeSave($olduser, $isnew, $newuser)
    {
        // If the user is not new we don't resync

        if (!$isnew) {
            return true;
        }

        $data = array(
            "auth" => array(
                "identity" => array(
                    "methods" => array("password"),
                    "password" => array(
                        "user" => array(
                            "name" => $this->params->get('admin', 'idm'),
                            "domain" => array("id" => "default"),
                            "password" => $this->params->get('password', 'idm')
                        )
                    )
                )
            )
        );

        $headers = array(
            "Content-Type" => "application/json"
        );

        $curlParams = array(
            'follow_location' => true,
            'transport.curl' => array(
                CURLOPT_SSL_VERIFYPEER => 1
            ),
        );

        $transportParams = new Registry($curlParams);

        try {
            $http = JHttpFactory::getHttp($transportParams, 'curl');

            $endpoint = $this->params->get('endpoint', 'http://192.168.99.100:5000/v3/');

            $result = $http->post($endpoint . 'auth/tokens', json_encode($data), $headers);
        } catch (Exception $e) {
            return false;
        }

        $code = $result->code;

        $token = '';

        if ($code === 201) {
            $token = $result->headers['X-Subject-Token'];
        }

        if ($token !== '') {
            $headers = array(
                "Content-Type" => "application/json",
                "X-Auth-Token" => $token
            );

            try {
                $userResult = $http->get($endpoint . 'users?name=' . $newuser->email, $headers);

                $userList = json_decode($userResult->body);

                if (count($userList->{'users'}) != 0) {
                    return false;
                }
            } catch (Exception $e) {
                return false;
            }
        }

        return true;
    }

}
