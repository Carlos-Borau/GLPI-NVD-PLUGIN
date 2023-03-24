<?php

define('PLUGIN_GLPISOFTWAREVULNERABILITYASSESSMENT_VERSION', '1.0.0');
define('PLUGIN_GLPISOFTWAREVULNERABILITYASSESSMENT_MIN_GLPI', '10.0.6');

/**
 * Init the hooks of the plugin
 *
 * @return void
 */
function plugin_init_glpisoftwarevulnerabilityassessment() {
   global $PLUGIN_HOOKS;

   $PLUGIN_HOOKS['csrf_compliant']['glpisoftwarevulnerabilityassessment'] = true;

   //some code here, like call to Plugin::registerClass(), populating PLUGIN_HOOKS, ...

   /**
    * 
    * @todo
    */ 
}

/**
 * Get the name and the version of the plugin - Needed
 *
 * @return array
 */
function plugin_version_glpisoftwarevulnerabilityassessment() {
   return [
      'name'           => 'GLPI Software Vulnerability Assessment',
      'shortname'      => 'glpisva',
      'version'        => PLUGIN_GLPISOFTWAREVULNERABILITYASSESSMENT_VERSION,
      'author'         => 'Carlos Borau González',
      'license'        => 'GLPv3',
      'homepage'       => 'https://github.com/Carlos-Borau/GLPI-Software-Vulnerability-Assessment',
      'requirements'   => [
         'glpi'   => [
            'min' => PLUGIN_GLPISOFTWAREVULNERABILITYASSESSMENT_MIN_GLPI
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
function plugin_glpisoftwarevulnerabilityassessment_check_prerequisites() {
   
    // Check that the GLPI version is compatible
    if (version_compare(GLPI_VERSION, PLUGIN_GLPISOFTWAREVULNERABILITYASSESSMENT_MIN_GLPI, 'lt')) {

        echo "This plugin Requires GLPI >=".PLUGIN_GLPISOFTWAREVULNERABILITYASSESSMENT_MIN_GLPI;

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
function plugin_glpisoftwarevulnerabilityassessment_check_config($verbose = false) {
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
function plugin_glpisoftwarevulnerabilityassessment_options() {
   return [
      Plugin::OPTION_AUTOINSTALL_DISABLED => true,
   ];
}