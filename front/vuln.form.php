<style>
    <?php include ("../nvd.css"); ?>
</style>

<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
$plugin = new Plugin();
if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
   Html::displayNotFoundError();
}

?>