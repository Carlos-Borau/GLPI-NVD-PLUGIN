<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
$plugin = new Plugin();
if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
   Html::displayNotFoundError();
}

if (isset($_POST['newApiKey'])) {

    $newApiKey = $_POST['newApiKey'];
    $oldApiKey = (isset($_POST['oldApiKey'])) ? $_POST['oldApiKey'] : NULL;

    updateApiKey($newApiKey, $oldApiKey);
} 

Html::redirect("{$CFG_GLPI['root_doc']}/front/config.form.php");

/**
 * Update NVD API key on plugin config
 *
 * @since 1.0.0
 *
 * @param string $newApiKey    New NVD API key
 * @param string $oldApiKey    Old NVD API key
 *
 * @return void
 */
function updateApiKey($newApiKey, $oldApiKey) {

    global $DB;

    if ($oldApiKey == NULL) {

        $DB->insert(
            'glpi_plugin_nvd_config', [
                'api_key' => $newApiKey
            ]
        );

    } else {

        $DB->update(
            'glpi_plugin_nvd_config', [
                'api_key' => $newApiKey
            ], [
                'api_key' => $oldApiKey
            ]
        );
    }
}

?>