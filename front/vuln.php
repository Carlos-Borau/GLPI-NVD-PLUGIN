<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
$plugin = new Plugin();
if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
   Html::displayNotFoundError();
}

//check for ACLs
if (PluginNvdVuln::canView()) {
   //View is granted: display the list.

   //Add page header
   Html::header(
      __('NVD', 'nvd'),
      $_SERVER['PHP_SELF'],
      'assets',
      'pluginvndvuln',
      'vuln'
   );

   Search::show('PluginNvdVuln');

   Html::footer();
} else {
   //View is not granted.
   Html::displayRightError();
}

?>