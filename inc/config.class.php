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

        $out  = '<form action="../plugins/nvd/front/config.form.php" method="POST">';
        $out .= Html::hidden('_glpi_csrf_token', array('value' => Session::getNewCSRFToken()));

        if ($currentApiKey != NULL) {
            $out .= Html::hidden('oldApiKey', array('value' => $currentApiKey));
        }

        $out .= '<div class="nvd_cpe_div">';
        $out .= '<div class="nvd_cpe_stack_collumn">';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<b class="nvd_cpe_title">' . __('NVD API key') . ':</b></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<input required class="nvd_cpe_wide_textinput" type="text" id="nvd_api_key" name="newApiKey" value="' . $currentApiKey . '"></div></div>';

        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<input type="submit" class="btn btn-primary" value="' . __('Save NVD plugin configuration') . '"></div></div></div>';
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