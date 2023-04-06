<?php
class PluginNvdVuln extends CommonDBTM {

    /**
    * Check if can view item
    *
    * @return boolean
    */
    static function canView() {
        return Config::canView();
    }

    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        return self::createTabEntry('Vuln');
    }

    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {
        
        $out =      "<form action=\"../plugins/nvd/front/vuln.form.php\" method=\"POST\">";
        $out .=     Html::hidden('_glpi_csrf_token', array('value' => Session::getNewCSRFToken()));
        $out .=     "<label for=\"part\">Part:</label>";
        $out .=     "<select id=\"part\" name=\"part\" required>";
        $out .=     "<option disabled selected value> -- select an option -- </option>";
        $out .=     "<option value=\"a\">a (Application)</option>";
        $out .=     "<option value=\"o\">o (Operating System)</option>";
        $out .=     "<option value=\"h\">h (Hardware)</option>";
        $out .=     "</select><br>";
        $out .=     "Vendor: <input type=\"text\" name=\"vendor\" required><br>";
        $out .=     "Product: <input type=\"text\" name=\"product\" required><br>";
        $out .=     "Version: <input type=\"text\" name=\"version\" required><br>";

        $out .=     "<input type=\"submit\">";
        $out .=     "</form>";

        echo $out;

        return true;
    }
     
    /**
    * @see CommonGLPI::getMenuName()
    **/
    static function getMenuName() {
        return __('Vuln');
    }

    public function showForm($ID, $options = []) {

        global $CFG_GLPI;

        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        if (!isset($options['display'])) {
            //display per default
            $options['display'] = true;
        }

        $params = $options;
        //do not display called elements per default; they'll be displayed or returned here
        $params['display'] = false;

        $out = '<tr>';
        $out .= '<th>' . __('My label', 'myexampleplugin') . '</th>';

        $objectName = autoName(
            $this->fields["name"],
            "name",
            (isset($options['withtemplate']) && $options['withtemplate']==2),
            $this->getType(),
            $this->fields["entities_id"]
        );

        $out .= '<td>';
        $out .= Html::autocompletionTextField(
            $this,
            'name',
            [
                'value'     => $objectName,
                'display'   => false
            ]
        );
        $out .= '</td>';

        $out .= $this->showFormButtons($params);

        if ($options['display'] == true) {
            echo $out;
        } else {
            return $out;
        }
    }
}