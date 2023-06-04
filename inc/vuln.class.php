<?php

class PluginNvdVuln extends CommonDBTM {

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

        $numVulnerabilities = 0;
        
        switch($item::getType()) {

            case Software::getType():

                $numVulnerabilities = self::countForSoftware($item);
                break;

            case Computer::getType():
            case Phone::getType():

                $numVulnerabilities = self::countForDevice($item);
                break;

            default:

                $numVulnerabilities = self::countForDashboard();
        }
        
        return self::createTabEntry(__('Vulnerabilities'), $numVulnerabilities);
    }

    /**
     * Count number of vulnerabilities related to a given software
     *
     * @since 1.0.0
     *
     * @param Software $item        Software item to look vulnerabilities for
     *
     * @return int                  Number of vulnerabilities found
     */
    private static function countForSoftware(Software $item) {

        global $DB;

        /***********************************************************************************************
         * Request vulnerabilities to which the given software's different versions are vulnerable
         * 
         *  SELECT vuln_id
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = glpi_softwareversions.id
         *  WHERE softwares_id = $item->getID()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                             'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                             'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                     'glpi_softwareversions' => 'id']]] ,
                             'WHERE' => ['softwares_id' => $item->getID()],
                             'GROUPBY' => 'vuln_id']);

        return $res->numrows();
    }

    /**
     * Count number of vulnerabilities related to a given device
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item      Device item to look vulnerabilities for
     *
     * @return int                  Number of vulnerabilities found
     */
    private static function countForDevice(CommonGLPI $item) {

        global $DB;

        /***********************************************************************************************
         * Request vulnerabilities to which the given device's different programs are vulnerable
         * 
         *  SELECT vuln_id
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_items_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *     glpi_items_softwareversions.softwareversions_id
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                                         'INNER JOIN' => ['glpi_items_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                                     'glpi_items_softwareversions' => 'softwareversions_id']]],
                                         'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()],
                                         'GROUPBY' => 'vuln_id']);

        return $res->numrows();
    }

    /**
     * Count total number of vulnerabilities
     *
     * @since 1.0.0
     *
     * @return int                  Number of vulnerabilities found
     */
    private static function countForDashboard() {

        global $DB;

        /***********************************************************************************************
         * Request every vulnerability registered
         * 
         *  SELECT vuln_id 
         *  FROM glpi_plugin_nvd_vulnerable_software_versions, glpi_items_softwareversions
         *  WHERE glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *        glpi_items_softwareversions.softwareversions_id
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => ['glpi_plugin_nvd_vulnerable_software_versions', 'glpi_items_softwareversions'],
                                         'FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                    'glpi_items_softwareversions' => 'softwareversions_id'],
                                         'GROUPBY' => 'vuln_id']);

        return $res->numrows();
    }

    /**
     * Display tab content for given item
     *
     * @since 1.0.0
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
     * @since 1.0.0
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
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = glpi_softwareversions.id
         *  WHERE softwares_id = $item->getID()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                                'vuln_id AS VULN_ID',
                                new QueryExpression("GROUP_CONCAT(`name`) AS `version`")
                             ],
                             'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                             'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                     'glpi_softwareversions' => 'id']]] ,
                             'WHERE' => ['softwares_id' => $item->getID()],
                             'GROUPBY' => 'vuln_id']);
        
        $vulnerabilities = PluginNvdDatabaseutils::pushResToArray($res, 'version', 'VULN_ID');

        /***********************************************************************************************
         * Request CPE vendor and product name associated with given software
         * 
         *  SELECT vendor_name, product_name
         *  FROM glpi_plugin_nvd_cpe_software_associations 
         *  WHERE softwares_id = $item->getID()
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['vendor_name', 'product_name'],
                                'FROM' => 'glpi_plugin_nvd_cpe_software_associations',
                                'WHERE' => ['softwares_id' => $item->getID()]]);

        if ($res->numrows() == 0) { return; }

        $row = $res->current();
        $filters = array(
            'vendor_name' => $row['vendor_name'], 
            'product_name' => $row['product_name']
        );

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of vulnerabilities associated with given software
        self::displayVulnerabilityList($res, $vulnerabilities, __('Versions'), $filters);
    }

    /**
     * Display tab content for given Device item
     *
     * @since 1.0.0
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
         *         GROUP_CONCAT(glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id) AS version
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_items_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *     glpi_items_softwareversions.softwareversions_id
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(`glpi_plugin_nvd_vulnerable_software_versions`.`softwareversions_id`) AS `version`")
                ],
                'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                'INNER JOIN' => ['glpi_items_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
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
     * @since 1.0.0
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
         *  FROM glpi_plugin_nvd_vulnerable_software_versions, glpi_items_softwareversions
         *  WHERE glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *        glpi_items_softwareversions.softwareversions_id
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(DISTINCT `itemtype`, ':', `items_id` ORDER BY `itemtype`, `items_id`) AS instances")
                ],
                'FROM' => ['glpi_plugin_nvd_vulnerable_software_versions', 'glpi_items_softwareversions'],
                'FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
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
     * @since 1.0.0
     *
     * @param array $vulnerabilityIDs       IDs of vulnerabilities to query
     *
     * @return DBmysqlIterator
     */
    private static function requestVulnerabilities($vulnerabilityIDs) {

        if (!$vulnerabilityIDs) { return []; }

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
     * Request list of description for a given vulnerability
     *
     * @since 1.0.0
     *
     * @param int $vulnID       ID of vulnerabilities to query
     *
     * @return DBmysqlIterator
     */
    private static function requestDescriptions($vulnID) {

        global $DB;

        /***********************************************************************************************
        * Request descriptions for a CVE record
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerability_descriptions
        *  WHERE vuln_id = $vulnID
        **********************************************************************************************/
        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerability_descriptions',
                'WHERE' => ['vuln_id' => $vulnID]]);

        return $res;
    }

    /**
     * Request list of configurations for a given vulnerability
     *
     * @since 1.0.0
     *
     * @param int   $vulnID         ID of vulnerabilities to query
     * @param array $filters        Optional query filters
     *
     * @return DBmysqlIterator
     */
    private static function requestConfigurations($vulnID, $filters) {

        global $DB;

        /***********************************************************************************************
        * Request configurations for a CVE record
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerability_configurations
        *  WHERE vuln_id = $vulnID AND $filters
        **********************************************************************************************/
        $condition = ['vuln_id' => $vulnID];

        if (!is_null($filters)) {
            $condition = array_merge($condition, $filters);
        }

        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerability_configurations',
                'WHERE' => $condition ]);

        return $res;
    }

    /**
     * Display list of vulnerabilities for the given item
     *
     * @since 1.0.0
     *
     * @param DBmysqlIterator   $DBQueryResult          Result of the CVE query
     * @param array             $vulnerableInstances    Array of vulnerability IDs and their instances
     * @param bool              $is_software            Whether or not to treat the instances as software versions or programs 
     *
     * @return void
     */
    private static function displayVulnerabilityList($DBQueryResult, $vulnerableInstances, $instance_name, $filters=NULL) {

        // If no vulnerabilities are found do not display anything
        if (!$vulnerableInstances) { return; }

        $table =    '<table class="center vuln-table">';
        $table .=   '<colgroup><col width="10%"/><col width="5%"/><col width="15%"/><col width="5%"/><col width="55%"/><col width="10%"/></colgroup>';
        $table .=   '<tr>';
        $table .=   '<th class="centered">' . __('Severity') . '</th>';
        $table .=   '<th class="centered">' . __('Score') . '</th>';
        $table .=   '<th class="centered">CVE-ID</th>';
        $table .=   '<th class="centered">' . mb_chr(0x2755, 'UTF-8') . '</th>';
        $table .=   '<th class="centered">' . __('Description') . '</th>';
        $table .=   '<th class="centered">' . $instance_name . '</th>';
        $table .=   '</tr>';

        foreach ($DBQueryResult as $id => $row) {

            $descriptions   = self::requestDescriptions($id);
            $description    = PluginNvdCverecord::getDescriptionForLanguage($descriptions);

            $configurations = self::requestConfigurations($id, $filters);
            $configuration_warning = PluginNvdCverecord::parseConfiguration($configurations, !is_null($filters));

            $table .= '<tr>';
            $table .= '<td class="centered">' . PluginNvdCverecord::getCvssScoreSeverity($row['base_score']) . '</td>';
            $table .= '<td class="centered">' . $row['base_score'] . '</td>';
            $table .= '<td class="centered"> <a href="' . PluginNvdCverecord::getCveNvdUrl($row['cve_id']) . '">' . $row['cve_id'] . '</a></td>';
            $table .= '<td class="centered" ' . $configuration_warning . '</td>';
            $table .= '<td class="justified">' . $description . '</td>';
            $table .= '<td class="centered">';
            $table .= $vulnerableInstances[$id];
            $table .= '</td>';
            $table .= '</tr>';
        }

        $table .= '</table>';

        echo $table;
    }
}

?>