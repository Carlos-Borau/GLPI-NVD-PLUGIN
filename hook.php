<?php

/**
 * Install hook
 *
 * @return boolean
 */
function plugin_nvd_install() {
   
   require_once(PLUGIN_NVD_DIR . '\installation\install.php');

   pluginNvdInstall();

   return true;
}

/**
 * Uninstall hook
 *
 * @return boolean
 */
function plugin_nvd_uninstall() {
   
   require_once(PLUGIN_NVD_DIR . '\installation\uninstall.php');

   pluginNvdUninstall();

   return true;
}

?>