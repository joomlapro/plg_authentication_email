<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  Authentication.Email
 * @copyright   Copyright (C) 2013 AtomTech, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

// No direct access.
defined('JPATH_BASE') or die;

/**
 * Email Authentication Plugin.
 *
 * @package     Joomla.Plugin
 * @subpackage  Authentication.Email
 * @since       3.1
 */
class PlgAuthenticationEmail extends JPlugin
{
	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @param   array   $credentials  Array holding the user credentials
	 * @param   array   $options      Array of extra options
	 * @param   object  &$response    Authentication response object
	 *
	 * @return  boolean
	 *
	 * @since   3.1
	 */
	function onUserAuthenticate($credentials, $options, & $response)
	{
		// Get the joomla version.
		$version = new JVersion;
		$jver = explode('.', $version->getShortVersion());

		if ($jver[0] == 3)
		{
			$success = JAuthentication::STATUS_SUCCESS;
			$failure = JAuthentication::STATUS_FAILURE;
		}
		else
		{
			$success = JAUTHENTICATE_STATUS_SUCCESS;
			$failure = JAUTHENTICATE_STATUS_FAILURE;
		}

		// For JLog.
		$response->type = 'Joomla';

		// Joomla does not like Blank passwords.
		if (empty($credentials['password']))
		{
			$response->status = $failure;
			$response->error_message = JText::_('JGLOBAL_AUTH_PASS_BLANK');
			return false;
		}

		// Initialiase variables.
		$db = JFactory::getDbo();
		$query = $db->getQuery(true);

		// Create the base select statement.
		$query->select('id, password');
		$query->from($db->quoteName('#__users'));
		$query->where($db->quoteName('email') . ' = ' . $db->quote($credentials['username']));

		// Set the query and load the result.
		$db->setQuery($query);
		$result = $db->loadObject();

		// Check for a database error.
		if ($db->getErrorNum())
		{
			JError::raiseWarning(500, $db->getErrorMsg());
			return null;
		}

		if ($result)
		{
			// Initialiase variables.
			$parts     = explode(':', $result->password);
			$crypt     = $parts[0];
			$salt      = @$parts[1];
			$testcrypt = JUserHelper::getCryptedPassword($credentials['password'], $salt);

			if ($crypt == $testcrypt)
			{
				// Bring this in line with the rest of the system.
				$user = JUser::getInstance($result->id);

				$response->username = $user->username;
				$response->email = $user->email;
				$response->fullname = $user->name;

				if (JFactory::getApplication()->isAdmin())
				{
					$response->language = $user->getParam('admin_language');
				}
				else
				{
					$response->language = $user->getParam('language');
				}

				$response->status = $success;
				$response->error_message = '';
			}
			else
			{
				$response->status = $failure;
				$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
			}
		}
		else
		{
			$response->status = $failure;
			$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
		}
	}
}
