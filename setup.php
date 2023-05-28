<?php

use Glpi\Plugin\Hooks;

define('PLUGIN_NVD_VERSION', '1.0.0');
define('PLUGIN_NVD_MIN_GLPI', '10.0.6');

define('PLUGIN_NVD_DIR', __DIR__);

/**
 * Init the hooks of the plugin and register plugin classes
 *
 * @return void
 */
function plugin_init_nvd() {
   global $PLUGIN_HOOKS;

   $PLUGIN_HOOKS['csrf_compliant']['nvd'] = true;

   Plugin::registerClass(PluginNvdConfig::class, ['addtabon' => 
      [Config::class
   ]]);

   Plugin::registerClass(PluginNvdVuln::class, ['addtabon' => 
      [Central::class,
       Computer::class,
       Phone::class,
       Software::class
   ]]);

   Plugin::registerClass(PluginNvdSoftwarecpe::class, ['addtabon' =>
      [Software::class
   ]]);

   Plugin::registerClass(PluginNvdUpdatevuln::class, ['addtabon' =>
      [Central::class
   ]]);

   $PLUGIN_HOOKS[Hooks::ADD_JAVASCRIPT]['nvd'] = 'js/nvd.js';
   $PLUGIN_HOOKS[Hooks::ADD_CSS]['nvd'] = 'css/nvd.css';

}

/**
 * Get the name and the version of the plugin - Needed
 *
 * @return array
 */
function plugin_version_nvd() {
   return [
      'name'           => 'NVD',
      'shortname'      => 'nvd',
      'version'        => PLUGIN_NVD_VERSION,
      'author'         => 'Carlos Borau González',
      'license'        => 'GLPv3',
      'homepage'       => 'https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN',
      'requirements'   => [
         'glpi'   => [
            'min' => PLUGIN_NVD_MIN_GLPI
         ]
      ]
   ];
}

/**
 * Optional : check prerequisites before install : may print errors or add to message after redirect
 *
 * @return boolean
 * 
 * @todo
 */
function plugin_nvd_check_prerequisites() {
   
    // Check that the GLPI version is compatible
    if (version_compare(GLPI_VERSION, PLUGIN_NVD_MIN_GLPI, 'lt')) {

        echo "This plugin Requires GLPI >=".PLUGIN_NVD_MIN_GLPI;

        return false;
    }

    return true;
}

/**
 * Check configuration process for plugin : need to return true if succeeded
 * Can display a message only if failure and $verbose is true
 *
 * @param boolean $verbose Enable verbosity. Default to false
 *
 * @return boolean
 * 
 * @todo
 */
function plugin_nvd_check_config($verbose = false) {
   if (true) { // Your configuration check
      return true;
   }

   if ($verbose) {
      echo "Installed, but not configured";
   }
   return false;
}

/**
 * Optional: defines plugin options.
 *
 * @return array
 */
function plugin_nvd_options() {
   return [
      Plugin::OPTION_AUTOINSTALL_DISABLED => true,
   ];
}