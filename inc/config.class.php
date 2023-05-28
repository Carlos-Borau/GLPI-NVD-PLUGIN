<?php

class PluginNvdConfig extends CommonGLPI {

    /**
     * Check if can view item
     *
     * @since 1.0.0
     *
     * @return boolean
     */
    static function canView() {
        
        return Config::canView();
    }

    /**
     * Get tab name for displayed item
     *
     * @since 1.0.0
     *
     * @return boolean
     */
    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        return self::createTabEntry(__('NVD Plugin'));
    }

    /**
     * Display tab content for config tab
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item       Config item
     * @param int $tabnum
     * @param int $withtemplate
     *
     * @return boolean
     */
    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        if ($item::getType() === Config::getType()) {
            self::displayConfig();
        }
        
        return true;
    }

    /**
     * Display tab content for config tab
     *
     * @since 1.0.0
     *
     * @return void
     */
    private static function displayConfig() {

        $currentApiKey = self::getCurrentApiKey();

        $out = '<form action="../plugins/nvd/front/config.form.php" method="POST">';
        $out .= Html::hidden('_glpi_csrf_token', array('value' => Session::getNewCSRFToken()));

        if ($currentApiKey != NULL) {
            $out .= Html::hidden('oldApiKey', array('value' => $currentApiKey));
        }

        $out .= '<input required type="text" name="newApiKey" value="' . $currentApiKey . '">';
        $out .= '<input type="submit" class="btn btn-primary" value="' . __('Set NVD Api Key') . '">';
        $out .= '</form>';

        echo $out;
    }

    /**
     * Queries the database and retrieves the NVD API key from the configutarion if existing
     *
     * @since 1.0.0
     *
     * @return string Current NVD API key
     */
    private static function getCurrentApiKey() {

        global $DB;

        $res = $DB->request(['SELECT' => 'api_key',
                             'FROM' => 'glpi_plugin_nvd_config']);

        if ($res->numrows() != 0) {
            $row = $res->current();

            return $row['api_key'];
        }

        return NULL;
    }
}

?>