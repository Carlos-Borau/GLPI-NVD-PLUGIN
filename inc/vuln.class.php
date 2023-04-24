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

    /**
    * Get tab name for displayed item
    *
    * @return boolean
    */
    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        return self::createTabEntry('Vuln');
    }

    /**
    * Display tab content for given item
    *
    * @param CommonGLPI $item       Item for which to display vulnerabilities
    * @param int $tabnum
    * @param int $withtemplate
    *
    * @return boolean
    */
    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        switch($item::getType()) {

            case Software::getType():

                self::displayForSoftware($item);
                break;

            case Computer::getType():
            case Phone::getType():

                self::displayForDevice($item);
                break;

            default:

                self::displayForDashboard();
        }
        
        return true;
    }

    /**
    * Display tab content for given Software item
    *
    * @param Software $item       Software item for which to display vulnerabilities
    *
    * @return void
    */
    private static function displayForSoftware(Software $item) {

        global $DB;

        /***********************************************************************************************
         * Request vulnerabilities to which the given software's different versions are vulnerable
         * 
         *  SELECT vuln_id AS VULN_ID, GROUP_CONCAT(name) AS version
         *  FROM glpi_plugin_nvd_vulnerable_versions 
         *  INNER JOIN glpi_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_versions.softwareversions_id = glpi_softwareversions.id
         *  WHERE softwares_id = $item->getID()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                                'vuln_id AS VULN_ID',
                                new QueryExpression("GROUP_CONCAT(`name`) AS `version`")
                             ],
                             'FROM' => 'glpi_plugin_nvd_vulnerable_versions',
                             'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_versions' => 'softwareversions_id',
                                                                                     'glpi_softwareversions' => 'id']]] ,
                             'WHERE' => ['softwares_id' => $item->getID()],
                             'GROUPBY' => 'vuln_id']);
        
        $vulnerabilities = [];

        foreach ($res as $id => $row) {
            $vulnerabilities[$row['VULN_ID']] = $row['version'];
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of vulnerabilities associated with given software
        self::displayVulnerabilityList($res, $vulnerabilities, __('Versions'));
    }

    /**
    * Display tab content for given Device item
    *
    * @param CommonGLPI $item       Device item for which to display vulnerabilities
    *
    * @return void
    */
    private static function displayForDevice(CommonGLPI $item) {

        global $DB, $CFG_GLPI;

        /***********************************************************************************************
         * Request vulnerabilities to which the given device's different programs are vulnerable
         * 
         *  SELECT vuln_id AS VULN_ID, 
         *         GROUP_CONCAT(glpi_plugin_nvd_vulnerable_versions.softwareversions_id) AS version
         *  FROM glpi_plugin_nvd_vulnerable_versions 
         *  INNER JOIN glpi_items_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_versions.softwareversions_id = 
         *     glpi_items_softwareversions.softwareversions_id
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(`glpi_plugin_nvd_vulnerable_versions`.`softwareversions_id`) AS `version`")
                ],
                'FROM' => 'glpi_plugin_nvd_vulnerable_versions',
                'INNER JOIN' => ['glpi_items_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_versions' => 'softwareversions_id',
                                                                              'glpi_items_softwareversions' => 'softwareversions_id']]],
                'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()],
                'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            /***********************************************************************************************
             * Request IDs and names from programs that are vulnerable to the obtained vulnerabilities
             * 
             *  SELECT DISTINCT glpi_softwares.id, glpi_softwares.name
             *  FROM glpi_softwares 
             *  INNER JOIN glpi_softwareversions 
             *  ON glpi_softwares.id = glpi_softwareversions.softwares_id
             *  WHERE glpi_softwareversions.id IN explode(',', $row['version'])
             **********************************************************************************************/
            $res_2 = $DB->request(['SELECT' => ['glpi_softwares.id', 'glpi_softwares.name'],
                                 'DISTINCT' => true,
                                 'FROM' => 'glpi_softwares',
                                 'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_softwares' => 'id',
                                                                                         'glpi_softwareversions' => 'softwares_id']]],
                                 'WHERE' => ['glpi_softwareversions.id' => explode(',', $row['version'])]]);

            $programs = [];

            //Transform names and IDs to liks to vulnerable programs in GLPI
            foreach ($res_2 as $id_2 => $row_2) {
                array_push($programs, '<a href="' . "{$CFG_GLPI['root_doc']}/front/software.form.php?id=" . $row_2['id'] . '">' . $row_2['name'] . '</a>');
            }
            
            $vulnerabilities[$row['VULN_ID']] = implode(',', $programs);
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of vulnerabilities associated with given device
        self::displayVulnerabilityList($res, $vulnerabilities, __('Programs'));
    }

    /**
    * Display tab content on central dashboard
    *
    * @return void
    */
    private static function displayForDashboard(){

        global $DB, $CFG_GLPI;

        /***********************************************************************************************
         * Request every vulnerability registered and the devices associated with it
         * 
         *  SELECT vuln_id AS VULN_ID, 
         *       GROUP_CONCAT(DISTINCT itemtype, ':', items_id ORDER BY itemtype, items_id) AS instances
         *  FROM glpi_plugin_nvd_vulnerable_versions, glpi_items_softwareversions
         *  WHERE glpi_plugin_nvd_vulnerable_versions.softwareversions_id = 
         *        glpi_items_softwareversions.softwareversions_id
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(DISTINCT `itemtype`, ':', `items_id` ORDER BY `itemtype`, `items_id`) AS instances")
                ],
                'FROM' => ['glpi_plugin_nvd_vulnerable_versions', 'glpi_items_softwareversions'],
                'FKEY' => ['glpi_plugin_nvd_vulnerable_versions' => 'softwareversions_id',
                           'glpi_items_softwareversions' => 'softwareversions_id'],
                'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            $instances = explode(',', $row['instances']);
            $instance_IDs = [];

            // Sort every device into it's corresponding category
            foreach ($instances as $id => $device) {

                [$item_type, $item_id] = explode(':', $device);
                $instance_IDs[strtolower($item_type)][] = $item_id;
            }

            // Request device names from corresponding tables
            foreach ($instance_IDs as $item_type => $IDs) {

                $table = 'glpi_' . $item_type . 's';

                /***********************************************************************************************
                 * Request device names for the device IDs associated with a vulnerability
                 * 
                 *  SELECT name
                 *  FROM 'glpi_' . $item_type . 's'
                 *  WHERE id IN $IDs
                 **********************************************************************************************/
                $res_2 = $DB->request(['SELECT' => new QueryExpression("GROUP_CONCAT(`name` ORDER BY `id`) AS names"),
                                       'FROM' => $table,
                                       'WHERE' => ['id' => $IDs]]);

                //Associate device types and names with their corresponding name
                $instance_IDs[$item_type] = array_combine($instance_IDs[$item_type], explode(',', $res_2->current()['names']));
            }

            $instances = [];

            // Transform names and IDs to liks to vulnerable devices in GLPI
            foreach ($instance_IDs as $item_type => $ID_names) {
                foreach ($ID_names as $ID => $name) {
                    array_push($instances, '<a href="' . "{$CFG_GLPI['root_doc']}/front/$item_type.form.php?id=" . $ID . '">' . $name . '</a>');
                }
            }

            $vulnerabilities[$row['VULN_ID']] = implode(',', $instances);
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of vulnerabilities associated with given device
        self::displayVulnerabilityList($res, $vulnerabilities, __('Devices'));
    }

    /**
    * Request list of vulnerabilities for the given item
    *
    * @param array $vulnerabilityIDs       IDs of vulnerabilities to query
    *
    * @return DBmysqlIterator
    */
    private static function requestVulnerabilities($vulnerabilityIDs) {

        global $DB;

        /***********************************************************************************************
        * Request information on the obtained CVE records 
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerabilities
        *  WHERE id IN array_keys($vulnerabilities)
        *  ORDER BY severity DESC
        **********************************************************************************************/
        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerabilities',
                'WHERE' => ['id' => $vulnerabilityIDs],
                'ORDER' => 'base_score DESC']);

        return $res;
    }

    /**
    * Display list of vulnerabilities for the given item
    *
    * @param array $DBQueryResult       Result of the CVE query
    * @param array $vulnerableInstances Array of vulnerability IDs and their instances
    * @param bool $is_software          Whether or not to treat the instances as software versions or programs 
    *
    * @return void
    */
    private static function displayVulnerabilityList($DBQueryResult, $vulnerableInstances, $instance_name) {

        $table =    '<table class="center">';
        $table .=   '<colgroup><col width="10%"/><col width="10%"/><col width="15%"/><col width="55%"/><col width="10%"/></colgroup>';
        $table .=   '<tr>';
        $table .=   '<th>' . __('Severity') . '</th>';
        $table .=   '<th>' . __('Score') . '</th>';
        $table .=   '<th>CVE-ID</th>';
        $table .=   '<th>' . __('Description') . '</th>';
        $table .=   '<th>' . $instance_name . '</th>';
        $table .=   '</tr>';

        foreach ($DBQueryResult as $id => $row) {

            $table .= '<tr>';
            $table .= '<td>' . $row['severity'] . '</td>';
            $table .= '<td>' . $row['base_score'] . '</td>';
            $table .= '<td> <a href="' . PluginNvdConnection::getCveNvdUrl($row['cve_id']) . '">' . $row['cve_id'] . '</a></td>';
            $table .= '<td>' . $row['description'] . '</td>';
            $table .= '<td>';
            $table .= $vulnerableInstances[$id];
            $table .= '</td>';
            $table .= '</tr>';
        }

        $table .= '</table>';

        echo $table;
    }

    /*
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
    */
}